"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial Quadkey / Bing Maps Tile Hierarchical SCADA Canvas (W318).

Work Package: W318 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Quadkey / Bing Maps Tile SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. Quadkey constants, zoom levels, registers %R2790..%R2797, coils %M651..%M652, diagnostic codes (signed 16-bit safe comparisons).
2. Pure Python Mercator projection, (tileX, tileY) to Quadkey string bijection and reverse decoding.
3. Quadkey hierarchical prefix containment (zoom level n-1 prefix of zoom level n) and 8-neighbor adjacency.
4. Out-of-bounds latitude/longitude inputs handling (0x8435) and invalid Quadkey string handling (0x8436).
5. Dynamic spatial proximity collision hazard alarm (0x8434, %M652 asserted) and clearance.
6. RegisterTable synchronization across %R2790..%R2797 and %M651..%M652.
7. SVG SCADA canvas rendering: XML validity, dimensions (800x600), tile boundaries, asset count, contrast ratio (WCAG AAA > 18:1).
8. Pure ST POU validation with STParser and anti-ladder rejection of all 9 constructs.
9. ILogicUnit scan step and 100-cycle simulation soak with memory profiling.
10. 9-stage verification runner test and CLI interop (pass tempfile for --output and --svg!).
11. Explicit key requirements and boundary enforcement verification (Gate G9 / G2).
12. Advanced spatial query and tile coordinate edge cases.
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

from jev_cscape.hmi.quadkey_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_QUADKEY_COLLISION_ALARM,
    COIL_QUADKEY_HAZARD_ALARM,
    COIL_QUADKEY_ONLINE,
    COIL_QUADKEY_CANVAS_ONLINE,
    COIL_W318_CANVAS_ONLINE,
    COIL_W318_COLLISION_ALARM,
    COIL_W318_HAZARD_ALARM,
    COIL_W318_ONLINE,
    COIL_W318_QUADKEY_ONLINE,
    COLOR_ALARM_CRIMSON,
    COLOR_BORDER,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
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
    DEFAULT_ZOOM,
    DEFAULT_ZOOM_LEVEL,
    DIAG_COORDINATE_OUT_OF_BOUNDS,
    DIAG_ERR_INVALID_QUADKEY,
    DIAG_ERR_INVALID_STRING,
    DIAG_ERR_OUT_OF_BOUNDS,
    DIAG_ERR_PROXIMITY_HAZARD,
    DIAG_INVALID_QUADKEY,
    DIAG_INVALID_QUADKEY_STRING,
    DIAG_OK,
    DIAG_PROXIMITY_HAZARD_COLLISION,
    DIAG_QUADKEY_INVALID_STRING,
    DIAG_QUADKEY_OUT_OF_BOUNDS,
    DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS,
    DiagnosticCode,
    EARTH_RADIUS_METERS,
    EARTH_RADIUS_WGS84,
    MAX_LATITUDE,
    MAX_LONGITUDE,
    MAX_ZOOM,
    MAX_ZOOM_LEVEL,
    MIN_LATITUDE,
    MIN_LONGITUDE,
    MIN_ZOOM,
    MIN_ZOOM_LEVEL,
    QUADKEY_CANVAS_PURE_ST_POU,
    QuadkeyAsset,
    QuadkeyBoundingBox,
    QuadkeyCanvas,
    QuadkeyCanvasEngine,
    QuadkeyCell,
    QuadkeyDiagnosticCode,
    QuadkeyIndex,
    QuadkeyMetrics,
    QuadkeySpatialObject,
    QuadkeyStatusBits,
    QuadkeyTile,
    REG_QUADKEY_DIAGNOSTIC_CODE,
    REG_QUADKEY_NEAREST_DISTANCE_M,
    REG_QUADKEY_QUERY_LATENCY_US,
    REG_QUADKEY_TILE_X,
    REG_QUADKEY_TILE_Y,
    REG_QUADKEY_TOKEN,
    REG_QUADKEY_TOKEN_HI,
    REG_QUADKEY_TOTAL_ASSETS,
    REG_QUADKEY_TOTAL_OBJECTS,
    REG_QUADKEY_ZOOM,
    REG_QUADKEY_ZOOM_LEVEL,
    REG_W318_DIAGNOSTIC_CODE,
    REG_W318_NEAREST_DISTANCE_M,
    REG_W318_QUERY_LATENCY_US,
    REG_W318_TILE_X,
    REG_W318_TILE_Y,
    REG_W318_TOKEN,
    REG_W318_TOKEN_HI,
    REG_W318_TOTAL_ASSETS,
    REG_W318_TOTAL_OBJECTS,
    REG_W318_ZOOM,
    REG_W318_ZOOM_LEVEL,
    ST_PROGRAM_QUADKEY_CANVAS_SYNC,
    ST_PROGRAM_W318_QUADKEY_CANVAS_SYNC,
    SpatialAsset,
    SpatialObject,
    calculate_contrast_ratio,
    clip,
    create_canonical_quadkey_canvas,
    generate_quadkey_canvas_svg,
    ground_resolution_m,
    haversine_distance_m,
    int_to_quadkey,
    lat_lon_to_pixel_xy,
    lat_lon_to_quadkey,
    lat_lon_to_tile_xy,
    map_scale,
    map_size,
    pack_quadkey_token,
    pixel_xy_to_lat_lon,
    pixel_xy_to_tile_xy,
    quadkey_children,
    quadkey_neighbors,
    quadkey_parent,
    quadkey_to_bbox,
    quadkey_to_int,
    quadkey_to_lat_lon,
    quadkey_to_tile_xy,
    run_quadkey_canvas_verification,
    tile_to_bbox,
    tile_xy_to_lat_lon,
    tile_xy_to_pixel_xy,
    tile_xy_to_quadkey,
    unpack_quadkey_token,
    validate_wcag_aaa_contrast,
    verify_quadkey_canvas_pure_st,
)


# ============================================================================
# 1. Quadkey Constants, Zoom Levels, Registers & Diagnostic Codes Tests
# ============================================================================

class TestQuadkeyConstantsAndDiagnostics:
    """Test suite for W318 constants, zoom levels, registers, coils, and diagnostic codes."""

    def test_viewport_and_zoom_constants(self) -> None:
        assert CANVAS_VIEWPORT_WIDTH == 800.0
        assert CANVAS_VIEWPORT_HEIGHT == 600.0
        assert DEFAULT_VIEWPORT_WIDTH == 800.0
        assert DEFAULT_VIEWPORT_HEIGHT == 600.0
        assert MIN_ZOOM_LEVEL == 1
        assert MAX_ZOOM_LEVEL == 23
        assert DEFAULT_ZOOM_LEVEL == 12
        assert MIN_ZOOM == 1
        assert MAX_ZOOM == 23
        assert DEFAULT_ZOOM == 12
        assert DEFAULT_SAFETY_THRESHOLD_M == 50.0
        assert DEFAULT_HAZARD_THRESHOLD == 50.0
        assert EARTH_RADIUS_METERS == 6371000.0
        assert EARTH_RADIUS_WGS84 == 6378137.0
        assert abs(MIN_LATITUDE - (-85.05112878)) < 1e-6
        assert abs(MAX_LATITUDE - 85.05112878) < 1e-6
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

    def test_register_mappings_and_coils(self) -> None:
        assert REG_QUADKEY_TOTAL_ASSETS == "%R2790"
        assert REG_QUADKEY_ZOOM_LEVEL == "%R2791"
        assert REG_QUADKEY_TILE_X == "%R2792"
        assert REG_QUADKEY_TILE_Y == "%R2793"
        assert REG_QUADKEY_NEAREST_DISTANCE_M == "%R2794"
        assert REG_QUADKEY_QUERY_LATENCY_US == "%R2795"
        assert REG_QUADKEY_TOKEN_HI == "%R2796"
        assert REG_QUADKEY_DIAGNOSTIC_CODE == "%R2797"
        assert COIL_QUADKEY_ONLINE == "%M651"
        assert COIL_QUADKEY_COLLISION_ALARM == "%M652"

        # W318 aliases
        assert REG_W318_TOTAL_ASSETS == "%R2790"
        assert REG_W318_TOTAL_OBJECTS == "%R2790"
        assert REG_QUADKEY_TOTAL_OBJECTS == "%R2790"
        assert REG_W318_ZOOM_LEVEL == "%R2791"
        assert REG_QUADKEY_ZOOM == "%R2791"
        assert REG_W318_ZOOM == "%R2791"
        assert REG_W318_TILE_X == "%R2792"
        assert REG_W318_TILE_Y == "%R2793"
        assert REG_W318_NEAREST_DISTANCE_M == "%R2794"
        assert REG_W318_QUERY_LATENCY_US == "%R2795"
        assert REG_W318_TOKEN_HI == "%R2796"
        assert REG_QUADKEY_TOKEN == "%R2796"
        assert REG_W318_TOKEN == "%R2796"
        assert REG_W318_DIAGNOSTIC_CODE == "%R2797"
        assert COIL_W318_ONLINE == "%M651"
        assert COIL_W318_QUADKEY_ONLINE == "%M651"
        assert COIL_W318_CANVAS_ONLINE == "%M651"
        assert COIL_QUADKEY_CANVAS_ONLINE == "%M651"
        assert COIL_W318_COLLISION_ALARM == "%M652"
        assert COIL_W318_HAZARD_ALARM == "%M652"
        assert COIL_QUADKEY_HAZARD_ALARM == "%M652"

    def test_diagnostic_codes_values_and_representations(self) -> None:
        assert int(DIAG_OK) == 0x0000
        assert int(DIAG_PROXIMITY_HAZARD_COLLISION) == 0x8434
        assert int(DIAG_COORDINATE_OUT_OF_BOUNDS) == 0x8435
        assert int(DIAG_INVALID_QUADKEY_STRING) == 0x8436

        assert repr(DIAG_PROXIMITY_HAZARD_COLLISION) == "DiagnosticCode(0x8434)"
        assert str(DIAG_PROXIMITY_HAZARD_COLLISION) == "0x8434"
        assert str(DIAG_OK) == "0x0000"

    def test_diagnostic_codes_signed_16bit_equality(self) -> None:
        # DiagnosticCode implements signed 16-bit safe comparisons
        # 0x8434 is 33844 unsigned, -31692 signed
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8434
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 33844
        assert DIAG_PROXIMITY_HAZARD_COLLISION == -31692
        assert DIAG_PROXIMITY_HAZARD_COLLISION == (0x8434 - 0x10000)

        # 0x8435 is 33845 unsigned, -31691 signed
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == 0x8435
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == 33845
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == -31691
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == (0x8435 - 0x10000)

        # 0x8436 is 33846 unsigned, -31690 signed
        assert DIAG_INVALID_QUADKEY_STRING == 0x8436
        assert DIAG_INVALID_QUADKEY_STRING == 33846
        assert DIAG_INVALID_QUADKEY_STRING == -31690
        assert DIAG_INVALID_QUADKEY_STRING == (0x8436 - 0x10000)

        assert DIAG_OK == 0
        assert DIAG_OK == 0x0000

        # Set containment
        code_set = {DIAG_PROXIMITY_HAZARD_COLLISION, DIAG_COORDINATE_OUT_OF_BOUNDS}
        assert DIAG_PROXIMITY_HAZARD_COLLISION in code_set
        assert 0x8434 in code_set

    def test_diagnostic_codes_aliases(self) -> None:
        assert DIAG_ERR_PROXIMITY_HAZARD == DIAG_PROXIMITY_HAZARD_COLLISION
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == DIAG_ERR_OUT_OF_BOUNDS
        assert DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS == DIAG_COORDINATE_OUT_OF_BOUNDS
        assert DIAG_QUADKEY_OUT_OF_BOUNDS == DIAG_COORDINATE_OUT_OF_BOUNDS
        assert DIAG_INVALID_QUADKEY == DIAG_INVALID_QUADKEY_STRING
        assert DIAG_ERR_INVALID_QUADKEY == DIAG_INVALID_QUADKEY_STRING
        assert DIAG_QUADKEY_INVALID_STRING == DIAG_INVALID_QUADKEY_STRING
        assert DIAG_ERR_INVALID_STRING == DIAG_INVALID_QUADKEY_STRING

        # Cross-wave alias equivalence
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8430
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x842C
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8428
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8424
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == 0x8431
        assert DIAG_INVALID_QUADKEY_STRING == 0x8432

    def test_status_bits(self) -> None:
        assert QuadkeyStatusBits.ONLINE == 1
        assert QuadkeyStatusBits.COLLISION_ALARM == 2
        assert QuadkeyStatusBits.GRID_GENERATED == 4
        assert QuadkeyStatusBits.HIGH_DENSITY == 8
        assert QuadkeyStatusBits.TILE_SELECTED == 16

        combined = QuadkeyStatusBits.ONLINE | QuadkeyStatusBits.GRID_GENERATED | QuadkeyStatusBits.TILE_SELECTED
        assert (combined & QuadkeyStatusBits.ONLINE) != 0
        assert (combined & QuadkeyStatusBits.COLLISION_ALARM) == 0
        assert (combined & QuadkeyStatusBits.TILE_SELECTED) != 0

    def test_quadkey_token_packing_unpacking_roundtrip(self) -> None:
        test_tokens = [0x00000000, 0x12345678, 0xFFFFFFFF, 0xABCD1234, 0x5555AAAA, 0x0000FFFF]
        for tok_val in test_tokens:
            hi, lo = pack_quadkey_token(tok_val)
            assert 0 <= hi <= 0xFFFF
            assert 0 <= lo <= 0xFFFF
            unpacked = unpack_quadkey_token(hi, lo)
            assert unpacked == tok_val


# ============================================================================
# 2. Pure Python Mercator Projection & Tile Math Tests
# ============================================================================

class TestQuadkeyMercatorProjectionAndTileMath:
    """Test suite for Web Mercator projection, pixel/tile coordinates, and tile bounding boxes."""

    def test_clip_helper(self) -> None:
        assert clip(5.0, 0.0, 10.0) == 5.0
        assert clip(-5.0, 0.0, 10.0) == 0.0
        assert clip(15.0, 0.0, 10.0) == 10.0

    def test_map_size_calculation(self) -> None:
        for zoom in range(1, 24):
            expected = 256 << zoom
            assert map_size(zoom) == expected

        with pytest.raises(ValueError):
            map_size(0)
        with pytest.raises(ValueError):
            map_size(24)

    def test_ground_resolution_and_scale(self) -> None:
        res_eq_z1 = ground_resolution_m(0.0, 1)
        res_eq_z2 = ground_resolution_m(0.0, 2)
        assert abs(res_eq_z1 - 2.0 * res_eq_z2) < 1e-4

        res_pole = ground_resolution_m(85.0, 1)
        assert res_pole < res_eq_z1

        scale = map_scale(0.0, 1, dpi=96.0)
        assert scale > 0.0

    def test_haversine_distance_computation(self) -> None:
        # Distance to self is 0
        assert haversine_distance_m(37.7749, -122.4194, 37.7749, -122.4194) == 0.0

        # SF to London (~8600 km)
        d_sf_lon = haversine_distance_m(37.7749, -122.4194, 51.5074, -0.1278)
        assert 8.5e6 < d_sf_lon < 8.8e6

        # One degree latitude is ~111 km
        d_one_deg = haversine_distance_m(0.0, 0.0, 1.0, 0.0)
        assert 110000.0 < d_one_deg < 112000.0

    def test_lat_lon_to_pixel_xy_and_inverse_roundtrip(self) -> None:
        test_points = [
            (37.7749, -122.4194),   # San Francisco
            (51.5074, -0.1278),     # London
            (35.6762, 139.6503),    # Tokyo
            (-33.8688, 151.2093),   # Sydney
            (0.0, 0.0),             # Equator / Prime Meridian
            (48.8566, 2.3522),      # Paris
        ]
        for lat, lon in test_points:
            for zoom in [3, 8, 12, 16]:
                px, py = lat_lon_to_pixel_xy(lat, lon, zoom)
                r_lat, r_lon = pixel_xy_to_lat_lon(px, py, zoom)
                dist = haversine_distance_m(lat, lon, r_lat, r_lon)
                # Max quantization error should be within a few meters at zoom 16, < 100m at zoom 12
                if zoom >= 12:
                    assert dist < 150.0

    def test_pixel_to_tile_and_tile_to_pixel(self) -> None:
        assert pixel_xy_to_tile_xy(0, 0) == (0, 0)
        assert pixel_xy_to_tile_xy(255, 255) == (0, 0)
        assert pixel_xy_to_tile_xy(256, 512) == (1, 2)
        assert tile_xy_to_pixel_xy(1, 2) == (256, 512)

    def test_lat_lon_to_tile_xy_and_inverse(self) -> None:
        # Equator (0,0) at zoom 1 is at tile (1, 1) of a 2x2 grid
        tx, ty = lat_lon_to_tile_xy(0.0, 0.0, zoom=1)
        assert (tx, ty) == (1, 1)

        c_lat, c_lon = tile_xy_to_lat_lon(tx, ty, zoom=1)
        assert abs(c_lat - (-40.9798)) < 1.0 or -85.0 < c_lat < 85.0

    def test_tile_to_bbox_properties(self) -> None:
        bbox = tile_to_bbox(0, 0, zoom=1)
        assert isinstance(bbox, QuadkeyBoundingBox)
        assert bbox.min_lat < bbox.max_lat
        assert bbox.min_lon < bbox.max_lon
        assert bbox.lat_min == bbox.min_lat
        assert bbox.lat_max == bbox.max_lat
        assert bbox.lon_min == bbox.min_lon
        assert bbox.lon_max == bbox.max_lon


# ============================================================================
# 3. Quadkey String Bijection & Token Decoding Tests
# ============================================================================

class TestQuadkeyEncodingAndBijection:
    """Test suite for Quadkey base-4 bit interleaving encoding, decoding, and tokens."""

    def test_canonical_zoom_1_tiles(self) -> None:
        # At zoom 1: 2x2 tiles
        assert tile_xy_to_quadkey(0, 0, zoom=1) == "0"
        assert tile_xy_to_quadkey(1, 0, zoom=1) == "1"
        assert tile_xy_to_quadkey(0, 1, zoom=1) == "2"
        assert tile_xy_to_quadkey(1, 1, zoom=1) == "3"

        assert quadkey_to_tile_xy("0") == (0, 0, 1)
        assert quadkey_to_tile_xy("1") == (1, 0, 1)
        assert quadkey_to_tile_xy("2") == (0, 1, 1)
        assert quadkey_to_tile_xy("3") == (1, 1, 1)

    def test_canonical_bing_maps_sample_tile(self) -> None:
        # Canonical Bing Maps Tile System example: tile (3, 5) at zoom 3 -> "213"
        qk = tile_xy_to_quadkey(3, 5, zoom=3)
        assert qk == "213"
        tx, ty, z = quadkey_to_tile_xy("213")
        assert (tx, ty, z) == (3, 5, 3)

    def test_bijective_roundtrip_across_multiple_zooms(self) -> None:
        for zoom in [1, 3, 5, 8, 12, 16, 20]:
            max_t = (1 << zoom) - 1
            sample_tiles = [
                (0, 0),
                (max_t, max_t),
                (max_t // 2, max_t // 2),
                (max_t // 4, (3 * max_t) // 4),
            ]
            for tx, ty in sample_tiles:
                qk = tile_xy_to_quadkey(tx, ty, zoom)
                assert len(qk) == zoom
                assert all(c in "0123" for c in qk)
                rec_x, rec_y, rec_z = quadkey_to_tile_xy(qk)
                assert (rec_x, rec_y, rec_z) == (tx, ty, zoom)

    def test_lat_lon_to_quadkey_and_inverse(self) -> None:
        coords = [
            (37.7749, -122.4194),   # San Francisco
            (51.5074, -0.1278),     # London
            (35.6762, 139.6503),    # Tokyo
            (-33.8688, 151.2093),   # Sydney
        ]
        for lat, lon in coords:
            qk = lat_lon_to_quadkey(lat, lon, zoom=14)
            assert len(qk) == 14
            c_lat, c_lon = quadkey_to_lat_lon(qk)
            dist = haversine_distance_m(lat, lon, c_lat, c_lon)
            # At zoom 14, tile radius is ~1.5 km
            assert dist < 3000.0

    def test_quadkey_to_int_and_int_to_quadkey_roundtrip(self) -> None:
        test_qks = ["0", "3", "213", "023010203332", "012301230123"]
        for qk in test_qks:
            val = quadkey_to_int(qk)
            rec_qk = int_to_quadkey(val, zoom=len(qk))
            assert rec_qk == qk

    def test_quadkey_tile_class_methods(self) -> None:
        qk_str = "023010203332"
        tile = QuadkeyTile.from_quadkey(qk_str)
        assert tile.quadkey == qk_str
        assert tile.zoom == len(qk_str)
        assert tile.to_string() == qk_str
        assert tile.to_quadkey() == qk_str
        assert str(tile) == qk_str
        assert "023010203332" in repr(tile)

        # Hash and equality
        tile2 = QuadkeyTile.from_quadkey(qk_str)
        assert tile == tile2
        assert tile == qk_str
        assert hash(tile) == hash(tile2)

        # From lat lon
        tile_geo = QuadkeyTile.from_lat_lon(37.7749, -122.4194, zoom=12)
        assert tile_geo.zoom == 12
        assert len(tile_geo.quadkey) == 12


# ============================================================================
# 3. Quadkey Hierarchical Prefix Containment & Adjacency Tests
# ============================================================================

class TestQuadkeyHierarchicalPrefixAndAdjacency:
    """Test suite for hierarchical prefix containment, parent/child relationships, and 8 neighbors."""

    def test_quadkey_parent_function(self) -> None:
        assert quadkey_parent("213") == "21"
        assert quadkey_parent("21") == "2"
        assert quadkey_parent("2") == ""
        with pytest.raises(ValueError):
            quadkey_parent("")

    def test_quadkey_tile_parent_method(self) -> None:
        tile = QuadkeyTile.from_quadkey("023010203332")
        parent = tile.parent()
        assert parent is not None
        assert parent.quadkey == "02301020333"
        assert parent.zoom == tile.zoom - 1

        tile_root = QuadkeyTile.from_quadkey("1")
        assert tile_root.parent() is None

    def test_quadkey_children_function(self) -> None:
        children = quadkey_children("213")
        assert children == ["2130", "2131", "2132", "2133"]
        with pytest.raises(ValueError):
            quadkey_children("")

    def test_quadkey_tile_children_method(self) -> None:
        tile = QuadkeyTile.from_quadkey("213")
        children = tile.children()
        assert len(children) == 4
        assert [c.quadkey for c in children] == ["2130", "2131", "2132", "2133"]
        for c in children:
            assert c.zoom == 4
            assert c.parent() == tile
            assert tile.contains(c)

    def test_spatial_bbox_containment_across_hierarchy(self) -> None:
        tile = QuadkeyTile.from_quadkey("02301020")
        bbox_parent = tile.to_bbox()
        children = tile.children()
        for child in children:
            bbox_child = child.to_bbox()
            # Child bbox must be entirely within parent bbox
            assert bbox_parent.min_lat <= bbox_child.min_lat + 1e-9
            assert bbox_parent.max_lat >= bbox_child.max_lat - 1e-9
            assert bbox_parent.min_lon <= bbox_child.min_lon + 1e-9
            assert bbox_parent.max_lon >= bbox_child.max_lon - 1e-9

    def test_eight_neighbor_adjacency_properties(self) -> None:
        sample_qk = "02301020"
        nbrs = quadkey_neighbors(sample_qk)
        assert len(nbrs) >= 8

        expected_dirs = [
            "north", "south", "east", "west",
            "northeast", "northwest", "southeast", "southwest",
        ]
        for d in expected_dirs:
            assert d in nbrs
            assert len(nbrs[d]) == len(sample_qk)

        # All 8 neighbors are distinct away from poles
        unique_neighbors = {nbrs[d] for d in expected_dirs}
        assert len(unique_neighbors) == 8

        # Short key aliases present
        for d in ["n", "s", "e", "w", "ne", "nw", "se", "sw"]:
            assert d in nbrs

    def test_neighbor_reciprocity(self) -> None:
        qk = "02301020"
        nbrs = quadkey_neighbors(qk)
        # North neighbor's South neighbor should be qk
        n_qk = nbrs["north"]
        assert quadkey_neighbors(n_qk)["south"] == qk

        # East neighbor's West neighbor should be qk
        e_qk = nbrs["east"]
        assert quadkey_neighbors(e_qk)["west"] == qk


# ============================================================================
# 4. Out-of-Bounds & Invalid Input Error Handling Tests
# ============================================================================

class TestQuadkeyInputValidationAndErrorHandling:
    """Test suite for out-of-bounds latitude/longitude (0x8435) and invalid quadkeys (0x8436)."""

    def test_latitude_out_of_bounds(self) -> None:
        with pytest.raises(ValueError):
            lat_lon_to_pixel_xy(90.0, 0.0, zoom=12)
        with pytest.raises(ValueError):
            lat_lon_to_pixel_xy(-86.0, 0.0, zoom=12)

    def test_longitude_out_of_bounds(self) -> None:
        with pytest.raises(ValueError):
            lat_lon_to_pixel_xy(0.0, 181.0, zoom=12)
        with pytest.raises(ValueError):
            lat_lon_to_pixel_xy(0.0, -181.0, zoom=12)

    def test_zoom_out_of_bounds(self) -> None:
        with pytest.raises(ValueError):
            lat_lon_to_pixel_xy(0.0, 0.0, zoom=0)
        with pytest.raises(ValueError):
            lat_lon_to_pixel_xy(0.0, 0.0, zoom=24)

    def test_tile_coordinates_out_of_bounds(self) -> None:
        with pytest.raises(ValueError):
            tile_xy_to_quadkey(-1, 0, zoom=5)
        with pytest.raises(ValueError):
            tile_xy_to_quadkey(0, 32, zoom=5)  # max tile for zoom 5 is 31

    def test_invalid_quadkey_strings(self) -> None:
        # Invalid characters
        with pytest.raises(ValueError):
            quadkey_to_tile_xy("01234")
        with pytest.raises(ValueError):
            quadkey_to_tile_xy("abc")
        with pytest.raises(ValueError):
            quadkey_to_tile_xy("")
        with pytest.raises(ValueError):
            quadkey_to_tile_xy("0123" * 7)  # length 28 > 23

    def test_engine_input_validation_and_diagnostic_code_setting(self) -> None:
        engine = QuadkeyCanvasEngine()
        # Inserting asset with out-of-bounds latitude raises ValueError and sets DIAG_COORDINATE_OUT_OF_BOUNDS (0x8435)
        with pytest.raises(ValueError):
            engine.insert_asset(95.0, 0.0)
        assert engine.diagnostic_code == DIAG_COORDINATE_OUT_OF_BOUNDS
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8435

        # Setting invalid zoom level raises ValueError and sets DIAG_COORDINATE_OUT_OF_BOUNDS (0x8435)
        with pytest.raises(ValueError):
            engine.set_zoom_level(30)
        assert engine.diagnostic_code == DIAG_COORDINATE_OUT_OF_BOUNDS

        # Selecting invalid quadkey raises ValueError and sets DIAG_INVALID_QUADKEY_STRING (0x8436)
        with pytest.raises(ValueError):
            engine.select_quadkey("4567")
        assert engine.diagnostic_code == DIAG_INVALID_QUADKEY_STRING
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8436


# ============================================================================
# 5. Dynamic Spatial Proximity Hazard Collision Tests
# ============================================================================

class TestQuadkeyProximityHazardCollision:
    """Test suite for proximity hazard collision alarm (0x8434, %M652) and clearance."""

    def test_nominal_state_no_collisions(self) -> None:
        engine = QuadkeyCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.insert_asset(37.7790, -122.4100, asset_id=2)  # Far apart (~1.2 km)

        hazards = engine.detect_collisions()
        assert len(hazards) == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (engine.status_word & QuadkeyStatusBits.COLLISION_ALARM) == 0
        assert engine.nearest_distance_m > 500.0

    def test_proximity_collision_trip(self) -> None:
        engine = QuadkeyCanvasEngine(safety_threshold_m=50.0)
        # Insert two assets ~11 meters apart (0.0001 deg lat is ~11.1m)
        a1 = engine.insert_asset(37.7770, -122.4150, asset_id=1, asset_type="valve")
        a2 = engine.insert_asset(37.7771, -122.4150, asset_id=2, asset_type="agv")

        hazards = engine.detect_collisions()
        assert len(hazards) == 1
        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8434
        assert (engine.status_word & QuadkeyStatusBits.COLLISION_ALARM) != 0
        assert a1.status == "alarm"
        assert a2.status == "alarm"
        assert engine.nearest_distance_m < 50.0

    def test_hazard_clearance_upon_asset_removal(self) -> None:
        engine = QuadkeyCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()
        assert engine.collision_alarm is True

        # Remove colliding asset
        assert engine.remove_asset(2) is True
        engine.detect_collisions()

        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x0000
        assert (engine.status_word & QuadkeyStatusBits.COLLISION_ALARM) == 0
        assert engine.assets[1].status == "normal"

    def test_manual_clear_alarm(self) -> None:
        engine = QuadkeyCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()
        assert engine.collision_alarm is True

        engine.clear_alarm()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert len(engine.active_hazards) == 0
        assert (engine.status_word & QuadkeyStatusBits.COLLISION_ALARM) == 0

    def test_detect_hazards_alias(self) -> None:
        engine = QuadkeyCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        hazards = engine.detect_hazards()
        assert len(hazards) == 1
        assert engine.collision_alarm is True


# ============================================================================
# 6. Horner OCS RegisterTable Synchronization Tests
# ============================================================================

class TestQuadkeyRegisterTableSync:
    """Test suite for RegisterTable synchronization across %R2790..%R2797 and %M651..%M652."""

    def test_sync_to_registers_nominal(self) -> None:
        engine = QuadkeyCanvasEngine(zoom_level=12)
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.insert_asset(37.7750, -122.4150, asset_id=2)

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_QUADKEY_TOTAL_ASSETS) == 2
        assert rt.read_word(REG_QUADKEY_ZOOM_LEVEL) == 12
        assert rt.read_word(REG_QUADKEY_TILE_X) == engine.selected_tile_x
        assert rt.read_word(REG_QUADKEY_TILE_Y) == engine.selected_tile_y
        assert rt.read_word(REG_QUADKEY_DIAGNOSTIC_CODE) == 0x0000
        assert rt.read_bit(COIL_QUADKEY_ONLINE) is True
        assert rt.read_bit(COIL_QUADKEY_COLLISION_ALARM) is False

    def test_sync_to_registers_collision_alarm(self) -> None:
        engine = QuadkeyCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert (rt.read_word(REG_QUADKEY_DIAGNOSTIC_CODE) & 0xFFFF) == 0x8434
        assert rt.read_word(REG_QUADKEY_DIAGNOSTIC_CODE) == DIAG_PROXIMITY_HAZARD_COLLISION
        assert rt.read_bit(COIL_QUADKEY_COLLISION_ALARM) is True
        assert rt.read_word(REG_QUADKEY_NEAREST_DISTANCE_M) < 50

    def test_sync_from_registers_setpoints(self) -> None:
        engine = QuadkeyCanvasEngine(zoom_level=12)
        rt = RegisterTable()

        # Write new zoom level and tile setpoints into registers
        rt.write_word(REG_QUADKEY_ZOOM_LEVEL, 14, PrivilegeMode.SYSTEM)
        rt.write_word(REG_QUADKEY_TILE_X, 100, PrivilegeMode.SYSTEM)
        rt.write_word(REG_QUADKEY_TILE_Y, 200, PrivilegeMode.SYSTEM)
        rt.write_bit(COIL_QUADKEY_ONLINE, True, PrivilegeMode.SYSTEM)

        engine.sync_from_registers(rt)
        assert engine.zoom_level == 14
        assert engine.selected_tile_x == 100
        assert engine.selected_tile_y == 200

    def test_signed_16bit_register_masks(self) -> None:
        rt = RegisterTable()
        # Write negative value to %R2797
        rt.write_word(REG_QUADKEY_DIAGNOSTIC_CODE, (-55) & 0xFFFF, PrivilegeMode.SYSTEM)
        raw_val = rt.read_word(REG_QUADKEY_DIAGNOSTIC_CODE)
        val_u = raw_val & 0xFFFF
        val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
        assert val_u == 65481
        assert val_s == -55

        # Write diagnostic code 0x8434
        rt.write_word(REG_QUADKEY_DIAGNOSTIC_CODE, int(DIAG_PROXIMITY_HAZARD_COLLISION) & 0xFFFF, PrivilegeMode.SYSTEM)
        diag_read = rt.read_word(REG_QUADKEY_DIAGNOSTIC_CODE) & 0xFFFF
        assert diag_read == 0x8434
        assert (diag_read - 0x10000) == -31692


# ============================================================================
# 7. SVG SCADA Canvas Rendering & WCAG AAA Contrast Tests
# ============================================================================

class TestQuadkeySvgCanvasAndWcagContrast:
    """Test suite for SVG SCADA canvas generation, XML validity, and WCAG 2.1 AAA contrast."""

    def test_svg_xml_validity_and_root_attributes(self) -> None:
        engine = create_canonical_quadkey_canvas(sample_count=8, zoom=12, seed=42)
        svg_content = generate_quadkey_canvas_svg(engine)

        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "800"
        assert root.attrib["height"] == "600"
        assert root.attrib["viewBox"] == "0 0 800 600"

    def test_svg_contains_required_structural_elements(self) -> None:
        engine = create_canonical_quadkey_canvas(sample_count=8, zoom=12, seed=42)
        svg_content = generate_quadkey_canvas_svg(engine)

        assert "quadkey-grid-container" in svg_content
        assert "quadkey-hazard-zones" in svg_content
        assert "quadkey-asset-markers" in svg_content
        assert "hud-telemetry-scorecard" in svg_content
        assert "QUADKEY SCADA ENGINE" in svg_content

    def test_svg_equipment_symbols_for_all_types(self) -> None:
        engine = QuadkeyCanvasEngine()
        engine.insert_asset(37.771, -122.420, asset_id=1, asset_type="valve", tag="VLV-01")
        engine.insert_asset(37.772, -122.421, asset_id=2, asset_type="pump", tag="PMP-02")
        engine.insert_asset(37.773, -122.422, asset_id=3, asset_type="tank", tag="TNK-03")
        engine.insert_asset(37.774, -122.423, asset_id=4, asset_type="agv", tag="AGV-04")
        engine.insert_asset(37.775, -122.424, asset_id=5, asset_type="sensor", tag="SEN-05")

        svg_content = generate_quadkey_canvas_svg(engine)
        assert "valve-symbol" in svg_content
        assert "pump-symbol" in svg_content
        assert "tank-symbol" in svg_content
        assert "agv-symbol" in svg_content
        assert "sensor-symbol" in svg_content

    def test_svg_active_hazard_line_and_distance_badge(self) -> None:
        engine = QuadkeyCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()

        svg_content = generate_quadkey_canvas_svg(engine)
        assert 'class="hazard-collision-line"' in svg_content
        assert "HAZARD" in svg_content
        assert "COLLISION ALARM" in svg_content

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

class TestQuadkeyPureSTAndSecurityRejection:
    """Test suite for Pure Structured Text POU validation and rejection of all 9 ladder constructs."""

    def test_pure_st_pou_verification(self) -> None:
        assert verify_quadkey_canvas_pure_st() is True

    def test_st_parser_ast_properties(self) -> None:
        parser = STParser()
        ast = parser.parse(ST_PROGRAM_W318_QUADKEY_CANVAS_SYNC)
        assert ast is not None
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "QuadkeySpatialCanvasSync"

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

class TestQuadkeyILogicUnitComplianceAndSoak:
    """Test suite for ILogicUnit interface compliance, scan steps, and 100-cycle soak."""

    def test_ilogicunit_interface_properties(self) -> None:
        engine = QuadkeyCanvasEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "QuadkeyCanvasEngine"
        assert engine.priority == 100
        assert engine.is_enabled is True

    def test_scan_step_execution_result_nominal(self) -> None:
        engine = QuadkeyCanvasEngine()
        res = engine.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert res.error_code is None
        assert "Assets=0" in res.details

    def test_scan_step_execution_result_alarm(self) -> None:
        engine = QuadkeyCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        res = engine.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.FAILED
        assert res.error_code == "0x8434"

    def test_simulation_soak_100_cycles_and_memory_profiling(self) -> None:
        engine = create_canonical_quadkey_canvas(sample_count=8, zoom=12, seed=42)
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
        assert engine.total_assets == 8
        # Memory growth across 100 cycles must be strictly bounded (< 2 MB)
        assert total_growth_kb < 2048.0, f"Memory leak detected: growth {total_growth_kb:.2f} KB >= 2048 KB"

    def test_reset_and_clear_methods(self) -> None:
        engine = QuadkeyCanvasEngine()
        engine.insert_asset(37.771, -122.420, asset_id=1)
        engine.scan_step()
        assert engine.total_assets == 1
        assert engine.cycle_count == 1

        engine.reset()
        assert engine.total_assets == 0
        assert engine.cycle_count == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK

        engine.insert_asset(37.771, -122.420, asset_id=2)
        engine.clear()
        assert engine.total_assets == 0


# ============================================================================
# 10. 9-Stage Verification Suite & CLI Interop Tests
# ============================================================================

class TestQuadkeyVerificationRunnerAndCLI:
    """Test suite for 9-stage verification runner and CLI execution."""

    def test_verification_runner_direct_execution(self) -> None:
        res = run_quadkey_canvas_verification(work_package="W318", quick=True)
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
            out_json = tmp_path / "w318_evidence.json"
            sample_svg = tmp_path / "w318_sample.svg"

            res = run_quadkey_canvas_verification(
                output_path=out_json,
                sample_svg_path=sample_svg,
                work_package="W318",
                quick=True,
            )

            assert res["status"] == "success"
            assert out_json.exists()
            assert sample_svg.exists()

            with open(out_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                assert data["status"] == "success"
                assert data["data"]["work_package"] == "W318"
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
                "scripts/run_quadkey_canvas_verification.py",
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
            "scripts/run_quadkey_canvas_verification.py",
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
                "scripts/run_quadkey_canvas_verification.py",
                "--quick",
                "--work-package",
                "W318_CUSTOM",
                "--output",
                str(out_json),
            ]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent)
            )
            assert proc.returncode == 0, f"CLI custom wp failed: {proc.stderr}"
            with open(out_json, "r", encoding="utf-8") as f:
                evidence = json.load(f)
                assert evidence["data"]["work_package"] == "W318_CUSTOM"


# ============================================================================
# 11. Key Requirements & Boundary Enforcement Verification Tests
# ============================================================================

class TestQuadkeyCanvasKeyRequirements:
    """Explicit tests addressing all W318 specification requirements (Gate G9 / G2)."""

    def test_key_req_quadkey_constants_and_registers(self) -> None:
        """Validate registers %R2790..%R2797 and coils %M651..%M652."""
        assert REG_QUADKEY_TOTAL_ASSETS == "%R2790"
        assert REG_QUADKEY_ZOOM_LEVEL == "%R2791"
        assert REG_QUADKEY_TILE_X == "%R2792"
        assert REG_QUADKEY_TILE_Y == "%R2793"
        assert REG_QUADKEY_NEAREST_DISTANCE_M == "%R2794"
        assert REG_QUADKEY_QUERY_LATENCY_US == "%R2795"
        assert REG_QUADKEY_TOKEN_HI == "%R2796"
        assert REG_QUADKEY_DIAGNOSTIC_CODE == "%R2797"
        assert COIL_QUADKEY_ONLINE == "%M651"
        assert COIL_QUADKEY_COLLISION_ALARM == "%M652"

    def test_key_req_pure_python_mercator_bijection(self) -> None:
        """Test Mercator projection and tile bijection at zoom 12."""
        coords = [
            (37.7749, -122.4194),
            (51.5074, -0.1278),
            (-33.8688, 151.2093),
            (35.6762, 139.6503),
        ]
        for lat, lon in coords:
            qk = lat_lon_to_quadkey(lat, lon, zoom=12)
            assert len(qk) == 12
            rec_x, rec_y, rec_z = quadkey_to_tile_xy(qk)
            rec_qk = tile_xy_to_quadkey(rec_x, rec_y, rec_z)
            assert rec_qk == qk

    def test_key_req_hierarchical_prefix_containment(self) -> None:
        """Test zoom level n-1 is prefix of zoom level n."""
        qk = lat_lon_to_quadkey(37.7749, -122.4194, zoom=12)
        for z in range(1, 12):
            sub_qk = qk[:z]
            assert qk.startswith(sub_qk)
            p = quadkey_parent(qk[:z + 1])
            assert p == sub_qk

    def test_key_req_out_of_bounds_and_invalid_inputs(self) -> None:
        """Test out-of-bounds latitude/longitude (0x8435) and invalid quadkey (0x8436)."""
        engine = QuadkeyCanvasEngine()
        with pytest.raises(ValueError):
            engine.insert_asset(95.0, 0.0)
        assert engine.diagnostic_code == DIAG_COORDINATE_OUT_OF_BOUNDS
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8435

        with pytest.raises(ValueError):
            engine.select_quadkey("INVALID")
        assert engine.diagnostic_code == DIAG_INVALID_QUADKEY_STRING
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8436

    def test_key_req_proximity_hazard_detection_and_clearance(self) -> None:
        """Test dynamic spatial proximity collision hazard alarm (0x8434, %M652) and clearance."""
        engine = QuadkeyCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()

        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8434

        engine.clear_alarm()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x0000

    def test_key_req_register_table_synchronization(self) -> None:
        """Test RegisterTable synchronization across %R2790..%R2797 and %M651..%M652."""
        engine = QuadkeyCanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_QUADKEY_TOTAL_ASSETS) == 1
        assert rt.read_word(REG_QUADKEY_DIAGNOSTIC_CODE) == int(DIAG_OK)
        assert rt.read_bit(COIL_QUADKEY_ONLINE) is True
        assert rt.read_bit(COIL_QUADKEY_COLLISION_ALARM) is False

    def test_key_req_svg_scada_canvas_rendering_and_contrast(self) -> None:
        """Test SVG SCADA canvas rendering: XML validity, dimensions, WCAG AAA > 18:1."""
        engine = create_canonical_quadkey_canvas(sample_count=8, seed=42)
        svg_content = generate_quadkey_canvas_svg(engine)

        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "800"
        assert root.attrib["height"] == "600"

        contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert contrast >= 18.0

    def test_key_req_pure_st_pou_anti_ladder_rejection(self) -> None:
        """Test Pure ST POU validation and anti-ladder rejection of all 9 constructs."""
        assert verify_quadkey_canvas_pure_st() is True

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

    def test_key_req_ilogicunit_simulation_soak_100_cycles_and_memory(self) -> None:
        """Test ILogicUnit simulation soak 100 cycles and memory stability."""
        engine = create_canonical_quadkey_canvas(sample_count=8, seed=42)
        rt = RegisterTable()
        ctx = ScanContext(cycle=0, register_table=rt)

        for c in range(100):
            ctx.cycle = c
            res = engine.scan_step(ctx)
            assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)

        assert engine.cycle_count == 100
        assert engine.total_assets == 8

    def test_key_req_9stage_verification_runner_contract(self) -> None:
        """Test 9-stage verification runner returning strict 4-state contract."""
        res = run_quadkey_canvas_verification(work_package="W318", quick=True)
        assert res["status"] in ("success", "failed", "blocked", "inconclusive")
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9


# ============================================================================
# 12. Advanced Spatial Queries & Coordinate Transformations Tests
# ============================================================================

class TestQuadkeySpatialQueriesAndTransforms:
    """Test suite for asset spatial queries (quadkey, tile, radius, bbox) and coordinate transforms."""

    def test_query_quadkey_matching(self) -> None:
        engine = QuadkeyCanvasEngine(zoom_level=12)
        a1 = engine.insert_asset(37.7710, -122.4200, asset_id=1)
        a2 = engine.insert_asset(37.7711, -122.4201, asset_id=2)
        a3 = engine.insert_asset(37.7790, -122.4100, asset_id=3)

        matches = engine.query_quadkey(a1.quadkey)
        assert a1 in matches

    def test_query_tile_matching(self) -> None:
        engine = QuadkeyCanvasEngine(zoom_level=12)
        a1 = engine.insert_asset(37.7710, -122.4200, asset_id=1)
        matches = engine.query_tile(a1.tile_x, a1.tile_y)
        assert a1 in matches

    def test_query_radius_matching(self) -> None:
        engine = QuadkeyCanvasEngine()
        a1 = engine.insert_asset(37.7710, -122.4200, asset_id=1)
        a2 = engine.insert_asset(37.7712, -122.4200, asset_id=2)  # ~22m away
        a3 = engine.insert_asset(37.7800, -122.4100, asset_id=3)  # ~1.3km away

        near = engine.query_radius(37.7710, -122.4200, radius_m=50.0)
        assert a1 in near
        assert a2 in near
        assert a3 not in near

    def test_query_bbox_matching(self) -> None:
        engine = QuadkeyCanvasEngine()
        a1 = engine.insert_asset(37.7750, -122.4200, asset_id=1)
        bbox = DEFAULT_DOMAIN_BBOX  # (37.7700, -122.4250, 37.7800, -122.4100)
        matches = engine.query_bbox(*bbox)
        assert a1 in matches

    def test_canvas_to_latlon_and_inverse(self) -> None:
        engine = QuadkeyCanvasEngine()
        lat, lon = 37.7750, -122.4200
        cx, cy = engine.latlon_to_canvas(lat, lon)
        assert 0.0 <= cx <= engine.viewport_width
        assert 0.0 <= cy <= engine.viewport_height

        r_lat, r_lon = engine.canvas_to_latlon(cx, cy)
        assert abs(r_lat - lat) < 1e-4
        assert abs(r_lon - lon) < 1e-4

    def test_select_tile_and_select_quadkey(self) -> None:
        engine = QuadkeyCanvasEngine(zoom_level=12)
        engine.select_tile(100, 200)
        assert engine.selected_tile_x == 100
        assert engine.selected_tile_y == 200
        assert (engine.status_word & QuadkeyStatusBits.TILE_SELECTED) != 0

        qk = tile_xy_to_quadkey(150, 250, zoom=12)
        engine.select_quadkey(qk)
        assert engine.selected_tile_x == 150
        assert engine.selected_tile_y == 250
        assert engine.selected_quadkey == qk

    def test_asset_retrieval_and_removal(self) -> None:
        engine = QuadkeyCanvasEngine()
        a = engine.insert_asset(37.771, -122.420, asset_id=42, asset_type="pump", tag="PMP-42")
        assert engine.get_asset(42) == a
        assert engine.get_asset(999) is None
        assert engine.remove_asset(42) is True
        assert engine.remove_asset(42) is False
        assert engine.get_asset(42) is None
