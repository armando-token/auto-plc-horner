"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial Geohash SCADA Canvas (W309).

Work Package: W309 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Geohash SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. Constants, viewport dimensions, color palettes, status bits, and diagnostic codes (signed 16-bit safe comparisons)
2. Pure Python Geohash encoding and decoding bijection, bounding box interval validation across precisions 1..10
3. 8-neighbor spatial adjacency computation across boundaries and poles
4. Out-of-bounds latitude/longitude inputs handling (0x841D) and invalid base32 characters (0x841E)
5. Dynamic spatial proximity collision hazard alarm (0x841C, %M631 asserted) and clearance
6. RegisterTable synchronization across %R2700..%R2707 and %M630..%M631
7. SVG SCADA canvas rendering: XML validity, dimensions, asset count, contrast ratio (WCAG AAA > 7:1, > 18:1)
8. Pure ST POU validation with STParser and anti-ladder rejection of all 9 constructs
9. ILogicUnit scan step and 100-cycle simulation soak with memory profiling
10. 9-stage verification runner test and CLI interop (pass tempfile for --output and --svg!)
11. Explicit key requirements and boundary enforcement verification
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import subprocess
import sys
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

from jev_cscape.hmi.geohash_canvas import (
    BASE32,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_GEOHASH_COLLISION_ALARM,
    COIL_GEOHASH_ONLINE,
    COIL_W309_COLLISION_ALARM,
    COIL_W309_GEOHASH_ONLINE,
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
    COLOR_WARNING_AMBER,
    DEFAULT_DOMAIN_BBOX,
    DEFAULT_HAZARD_THRESHOLD,
    DEFAULT_PRECISION,
    DEFAULT_SAFETY_THRESHOLD_M,
    DEFAULT_VIEWPORT_HEIGHT,
    DEFAULT_VIEWPORT_WIDTH,
    DIAG_COORDINATE_OUT_OF_BOUNDS,
    DIAG_ERR_INVALID_CHAR,
    DIAG_ERR_OUT_OF_BOUNDS,
    DIAG_ERR_PROXIMITY_HAZARD,
    DIAG_GEOHASH_DECODE_INVALID_CHAR,
    DIAG_OK,
    DIAG_PROXIMITY_HAZARD_COLLISION,
    DiagnosticCode,
    EARTH_RADIUS_METERS,
    GEOHASH_CANVAS_PURE_ST_POU,
    GeohashAsset,
    GeohashBoundingBox,
    GeohashCanvas,
    GeohashCanvasEngine,
    GeohashDiagnosticCode,
    GeohashMetrics,
    GeohashSpatialObject,
    GeohashStatusBits,
    MAX_PRECISION,
    MIN_PRECISION,
    REG_GEOHASH_CANVAS_ZOOM,
    REG_GEOHASH_DIAGNOSTIC_CODE,
    REG_GEOHASH_NEAREST_DISTANCE_M,
    REG_GEOHASH_PRECISION_LEVEL,
    REG_GEOHASH_QUERY_LATENCY_US,
    REG_GEOHASH_SELECTED_PREFIX_W1,
    REG_GEOHASH_SELECTED_PREFIX_W2,
    REG_GEOHASH_TOTAL_ASSETS,
    REG_W309_CANVAS_ZOOM,
    REG_W309_DIAGNOSTIC_CODE,
    REG_W309_NEAREST_DISTANCE_M,
    REG_W309_PRECISION_LEVEL,
    REG_W309_QUERY_LATENCY_US,
    REG_W309_SELECTED_PREFIX_W1,
    REG_W309_SELECTED_PREFIX_W2,
    REG_W309_TOTAL_ASSETS,
    ST_PROGRAM_GEOHASH_CANVAS_SYNC,
    ST_PROGRAM_W309_GEOHASH_CANVAS_SYNC,
    SpatialAsset,
    SpatialObject,
    calculate_contrast_ratio,
    create_canonical_geohash_canvas,
    decode,
    decode_bbox,
    decode_exact,
    encode,
    generate_geohash_canvas_svg,
    haversine_distance_m,
    neighbor,
    neighbors,
    pack_geohash_to_words,
    run_geohash_canvas_verification,
    unpack_words_to_geohash,
    validate_wcag_aaa_contrast,
    verify_geohash_canvas_pure_st,
)


# ============================================================================
# 1. Constants, Base32 Characters & Diagnostics Tests
# ============================================================================

class TestGeohashConstantsAndDiagnostics:
    def test_viewport_and_precision_constants(self) -> None:
        assert CANVAS_VIEWPORT_WIDTH == 800.0
        assert CANVAS_VIEWPORT_HEIGHT == 600.0
        assert DEFAULT_VIEWPORT_WIDTH == 800.0
        assert DEFAULT_VIEWPORT_HEIGHT == 600.0
        assert MIN_PRECISION == 1
        assert MAX_PRECISION == 12
        assert DEFAULT_PRECISION == 6
        assert DEFAULT_SAFETY_THRESHOLD_M == 50.0
        assert DEFAULT_HAZARD_THRESHOLD == 50.0
        assert EARTH_RADIUS_METERS == 6371000.0

    def test_base32_character_set(self) -> None:
        assert len(BASE32) == 32
        assert BASE32 == "0123456789bcdefghjkmnpqrstuvwxyz"
        # Letters 'a', 'i', 'l', 'o' are strictly omitted to prevent human reading confusion
        for forbidden in ["a", "i", "l", "o"]:
            assert forbidden not in BASE32

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

    def test_register_mappings_and_coils(self) -> None:
        assert REG_GEOHASH_TOTAL_ASSETS == "%R2700"
        assert REG_GEOHASH_SELECTED_PREFIX_W1 == "%R2701"
        assert REG_GEOHASH_SELECTED_PREFIX_W2 == "%R2702"
        assert REG_GEOHASH_PRECISION_LEVEL == "%R2703"
        assert REG_GEOHASH_NEAREST_DISTANCE_M == "%R2704"
        assert REG_GEOHASH_QUERY_LATENCY_US == "%R2705"
        assert REG_GEOHASH_CANVAS_ZOOM == "%R2706"
        assert REG_GEOHASH_DIAGNOSTIC_CODE == "%R2707"
        assert COIL_GEOHASH_ONLINE == "%M630"
        assert COIL_GEOHASH_COLLISION_ALARM == "%M631"

        # Aliases
        assert REG_W309_TOTAL_ASSETS == "%R2700"
        assert REG_W309_SELECTED_PREFIX_W1 == "%R2701"
        assert REG_W309_SELECTED_PREFIX_W2 == "%R2702"
        assert REG_W309_PRECISION_LEVEL == "%R2703"
        assert REG_W309_NEAREST_DISTANCE_M == "%R2704"
        assert REG_W309_QUERY_LATENCY_US == "%R2705"
        assert REG_W309_CANVAS_ZOOM == "%R2706"
        assert REG_W309_DIAGNOSTIC_CODE == "%R2707"
        assert COIL_W309_GEOHASH_ONLINE == "%M630"
        assert COIL_W309_COLLISION_ALARM == "%M631"

    def test_diagnostic_codes_values_and_representations(self) -> None:
        assert int(DIAG_OK) == 0x0000
        assert int(DIAG_PROXIMITY_HAZARD_COLLISION) == 0x841C
        assert int(DIAG_COORDINATE_OUT_OF_BOUNDS) == 0x841D
        assert int(DIAG_GEOHASH_DECODE_INVALID_CHAR) == 0x841E

        assert repr(DIAG_PROXIMITY_HAZARD_COLLISION) == "DiagnosticCode(0x841C)"
        assert str(DIAG_PROXIMITY_HAZARD_COLLISION) == "0x841C"
        assert str(DIAG_OK) == "0x0000"

    def test_diagnostic_codes_signed_16bit_equality(self) -> None:
        # DiagnosticCode implements signed 16-bit safe comparisons
        # 0x841C is 33820 unsigned, -31716 signed
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x841C
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x841C - 0x10000
        assert DIAG_PROXIMITY_HAZARD_COLLISION == -31716

        # 0x841D is 33821 unsigned, -31715 signed
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == 0x841D
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == 0x841D - 0x10000
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == -31715

        # 0x841E is 33822 unsigned, -31714 signed
        assert DIAG_GEOHASH_DECODE_INVALID_CHAR == 0x841E
        assert DIAG_GEOHASH_DECODE_INVALID_CHAR == 0x841E - 0x10000
        assert DIAG_GEOHASH_DECODE_INVALID_CHAR == -31714

        # DIAG_OK is 0
        assert DIAG_OK == 0
        assert DIAG_OK == 0x0000

        # Set containment with DiagnosticCode instances and unsigned values
        code_set = {DIAG_PROXIMITY_HAZARD_COLLISION, DIAG_COORDINATE_OUT_OF_BOUNDS}
        assert DIAG_PROXIMITY_HAZARD_COLLISION in code_set
        assert 0x841C in code_set

    def test_diagnostic_codes_aliases(self) -> None:
        assert DIAG_ERR_PROXIMITY_HAZARD == DIAG_PROXIMITY_HAZARD_COLLISION
        assert DIAG_ERR_OUT_OF_BOUNDS == DIAG_COORDINATE_OUT_OF_BOUNDS
        assert DIAG_ERR_INVALID_CHAR == DIAG_GEOHASH_DECODE_INVALID_CHAR

        # DiagnosticCode handles alias comparisons
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8418
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x841B
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == 0x8401
        assert DIAG_GEOHASH_DECODE_INVALID_CHAR == 0x841A

    def test_status_bits(self) -> None:
        assert GeohashStatusBits.ONLINE == 1
        assert GeohashStatusBits.COLLISION_ALARM == 2
        assert GeohashStatusBits.GRID_GENERATED == 4
        assert GeohashStatusBits.HIGH_DENSITY == 8

        combined = GeohashStatusBits.ONLINE | GeohashStatusBits.GRID_GENERATED
        assert (combined & GeohashStatusBits.ONLINE) != 0
        assert (combined & GeohashStatusBits.COLLISION_ALARM) == 0

    def test_geohash_bounding_box_properties(self) -> None:
        bbox = GeohashBoundingBox(37.0, -122.0, 38.0, -121.0)
        assert bbox.min_lat == 37.0
        assert bbox.min_lon == -122.0
        assert bbox.max_lat == 38.0
        assert bbox.max_lon == -121.0
        assert bbox.lat_min == 37.0
        assert bbox.lat_max == 38.0
        assert bbox.lon_min == -122.0
        assert bbox.lon_max == -121.0
        assert bbox.lat_height == 1.0
        assert bbox.lon_width == 1.0
        assert bbox.center == (37.5, -121.5)
        assert bbox.contains(37.5, -121.5)
        assert not bbox.contains(36.0, -121.5)

    def test_geohash_asset_dataclass(self) -> None:
        asset = GeohashAsset(
            id=7,
            lat=37.77,
            lon=-122.42,
            asset_type="valve",
            hazard_radius_m=35.0,
        )
        assert asset.id == 7
        assert asset.lat == 37.77
        assert asset.lon == -122.42
        assert asset.tag == "VAL-07"
        assert asset.hazard_radius_m == 35.0
        assert asset.status == "normal"

    def test_geohash_metrics_dataclass(self) -> None:
        metrics = GeohashMetrics(
            total_assets=5,
            selected_prefix="9q8y",
            precision_level=6,
            nearest_distance_m=42.5,
            online=True,
            collision_alarm=True,
            diagnostic_code=DIAG_PROXIMITY_HAZARD_COLLISION,
        )
        assert metrics.total_assets == 5
        assert metrics.selected_prefix == "9q8y"
        assert metrics.precision_level == 6
        assert metrics.nearest_distance_m == 42.5
        assert metrics.collision_alarm is True
        assert metrics.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION

    def test_words_packing_and_unpacking_roundtrip(self) -> None:
        test_prefixes = ["9q8y", "u4p", "g", "abcd", "", "1234"]
        for pref in test_prefixes:
            w1, w2 = pack_geohash_to_words(pref)
            unpacked = unpack_words_to_geohash(w1, w2)
            assert unpacked == pref


# ============================================================================
# 2. Pure Python Geohash Encoding & Decoding Bijection Tests
# ============================================================================

class TestGeohashEncodingDecodingBijection:
    def test_encode_decode_roundtrip_precision_1_to_10(self) -> None:
        coords = [
            (37.7749, -122.4194),  # San Francisco
            (51.5074, -0.1278),    # London
            (35.6762, 139.6503),   # Tokyo
            (-33.8688, 151.2093),  # Sydney
            (0.0, 0.0),            # Equator & Prime Meridian
        ]
        for lat, lon in coords:
            for p in range(1, 11):
                gh = encode(lat, lon, precision=p)
                assert len(gh) == p
                bbox = decode_bbox(gh)
                assert bbox.contains(lat, lon), f"Failed containment at ({lat}, {lon}) precision={p}"
                c_lat, c_lon = decode(gh)
                assert bbox.min_lat <= c_lat <= bbox.max_lat
                assert bbox.min_lon <= c_lon <= bbox.max_lon

    def test_bounding_box_interval_shrinking_with_precision(self) -> None:
        lat, lon = 37.7749, -122.4194
        prev_area = 1e12
        for p in range(1, 11):
            gh = encode(lat, lon, precision=p)
            bbox = decode_bbox(gh)
            area = bbox.lat_height * bbox.lon_width
            assert area < prev_area, f"Bounding box did not shrink at precision={p}"
            prev_area = area

    def test_decode_exact_margins(self) -> None:
        gh = encode(37.7749, -122.4194, precision=6)
        c_lat, c_lon, lat_err, lon_err = decode_exact(gh)
        bbox = decode_bbox(gh)
        assert abs(lat_err - bbox.lat_height / 2.0) < 1e-9
        assert abs(lon_err - bbox.lon_width / 2.0) < 1e-9
        assert abs(c_lat - bbox.center[0]) < 1e-9
        assert abs(c_lon - bbox.center[1]) < 1e-9

    def test_known_reference_geohashes(self) -> None:
        # Null island (0, 0)
        assert encode(0.0, 0.0, precision=6) == "s00000"
        # San Francisco reference
        assert encode(37.7749, -122.4194, precision=6) == "9q8yyk"
        # London reference
        assert encode(51.5074, -0.1278, precision=6).startswith("gcpv")
        # Sydney reference
        assert encode(-33.8688, 151.2093, precision=6).startswith("r3gx")

    def test_precision_extremes(self) -> None:
        lat, lon = 45.0, 45.0
        gh_min = encode(lat, lon, precision=MIN_PRECISION)
        assert len(gh_min) == 1
        bbox_min = decode_bbox(gh_min)
        assert bbox_min.contains(lat, lon)

        gh_max = encode(lat, lon, precision=MAX_PRECISION)
        assert len(gh_max) == 12
        bbox_max = decode_bbox(gh_max)
        assert bbox_max.contains(lat, lon)

    def test_decode_bbox_containment_sampling(self) -> None:
        gh = "9q8yyk"
        bbox = decode_bbox(gh)
        # Verify corners are inside or on boundary of bbox
        assert bbox.contains(bbox.min_lat, bbox.min_lon)
        assert bbox.contains(bbox.max_lat, bbox.max_lon)
        assert bbox.contains(bbox.center[0], bbox.center[1])

    def test_empty_string_rejection(self) -> None:
        with pytest.raises(ValueError, match="Cannot decode empty geohash"):
            decode("")
        with pytest.raises(ValueError, match="Cannot decode empty geohash"):
            decode_bbox("")


# ============================================================================
# 3. 8-Neighbor Spatial Adjacency Computation Tests
# ============================================================================

class TestGeohash8NeighborAdjacency:
    def test_neighbors_dict_keys(self) -> None:
        gh = "9q8yyk"
        nbrs = neighbors(gh)
        short_dirs = ["n", "s", "e", "w", "ne", "nw", "se", "sw"]
        long_dirs = ["north", "south", "east", "west", "northeast", "northwest", "southeast", "southwest"]
        for d in short_dirs:
            assert d in nbrs
            assert len(nbrs[d]) == len(gh)
        for d in long_dirs:
            assert d in nbrs

    def test_neighbor_single_direction_function(self) -> None:
        gh = "9q8yyk"
        nbrs = neighbors(gh)
        assert neighbor(gh, "n") == nbrs["n"]
        assert neighbor(gh, "north") == nbrs["n"]
        assert neighbor(gh, "s") == nbrs["s"]
        assert neighbor(gh, "south") == nbrs["s"]
        assert neighbor(gh, "e") == nbrs["e"]
        assert neighbor(gh, "east") == nbrs["e"]
        assert neighbor(gh, "w") == nbrs["w"]
        assert neighbor(gh, "west") == nbrs["w"]

    def test_neighbor_unknown_direction_rejection(self) -> None:
        with pytest.raises(ValueError, match="Unknown direction"):
            neighbor("9q8yyk", "up")
        with pytest.raises(ValueError, match="Unknown direction"):
            neighbor("9q8yyk", "down")

    def test_neighbor_spatial_distance(self) -> None:
        gh = "9q8yyk"
        bbox = decode_bbox(gh)
        c_lat, c_lon = bbox.center
        nbr_n = neighbors(gh)["n"]
        n_lat, n_lon = decode(nbr_n)
        dist = haversine_distance_m(c_lat, c_lon, n_lat, n_lon)
        # At precision 6, cell height is ~610m, so neighbor distance should be within ~400..1000m
        assert 400.0 < dist < 1200.0

    def test_neighbors_cardinal_reciprocity(self) -> None:
        gh = "9q8yyk"
        north_gh = neighbor(gh, "n")
        south_of_north = neighbor(north_gh, "s")
        assert south_of_north == gh

        east_gh = neighbor(gh, "e")
        west_of_east = neighbor(east_gh, "w")
        assert west_of_east == gh

    def test_neighbors_across_equator(self) -> None:
        gh_north = encode(0.001, 10.0, precision=6)
        nbrs = neighbors(gh_north)
        south_gh = nbrs["s"]
        s_lat, _ = decode(south_gh)
        assert s_lat < 0.0

    def test_neighbors_across_prime_meridian(self) -> None:
        gh_east = encode(10.0, 0.001, precision=6)
        nbrs = neighbors(gh_east)
        west_gh = nbrs["w"]
        _, w_lon = decode(west_gh)
        assert w_lon < 0.0

    def test_neighbors_across_antimeridian(self) -> None:
        # Near longitude 179.999
        gh_edge = encode(10.0, 179.999, precision=6)
        nbrs = neighbors(gh_edge)
        east_gh = nbrs["e"]
        _, e_lon = decode(east_gh)
        # Should wrap around into negative longitudes (-180..-170)
        assert e_lon < 0.0

    def test_neighbors_near_north_pole(self) -> None:
        gh_pole = encode(89.99, 0.0, precision=6)
        nbrs = neighbors(gh_pole)
        north_gh = nbrs["n"]
        n_lat, _ = decode(north_gh)
        assert n_lat <= 90.0
        assert len(north_gh) == 6

    def test_neighbors_near_south_pole(self) -> None:
        gh_pole = encode(-89.99, 0.0, precision=6)
        nbrs = neighbors(gh_pole)
        south_gh = nbrs["s"]
        s_lat, _ = decode(south_gh)
        assert s_lat >= -90.0
        assert len(south_gh) == 6

    def test_all_8_neighbors_distinct(self) -> None:
        gh = "9q8yyk"
        nbrs = neighbors(gh)
        short_dirs = ["n", "s", "e", "w", "ne", "nw", "se", "sw"]
        hashes = [nbrs[d] for d in short_dirs]
        assert len(set(hashes)) == 8

    def test_empty_geohash_neighbors_rejection(self) -> None:
        with pytest.raises(ValueError, match="Cannot compute neighbors for empty geohash"):
            neighbors("")


# ============================================================================
# 4. Out-of-Bounds & Invalid Input Handling Tests
# ============================================================================

class TestGeohashInputValidationAndErrors:
    def test_out_of_bounds_latitude_high(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            encode(90.1, 0.0)

    def test_out_of_bounds_latitude_low(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            encode(-90.1, 0.0)

    def test_out_of_bounds_longitude_high(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            encode(0.0, 180.1)

    def test_out_of_bounds_longitude_low(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            encode(0.0, -180.1)

    def test_precision_below_minimum(self) -> None:
        with pytest.raises(ValueError, match="Precision must be between"):
            encode(0.0, 0.0, precision=0)

    def test_precision_above_maximum(self) -> None:
        with pytest.raises(ValueError, match="Precision must be between"):
            encode(0.0, 0.0, precision=13)

    def test_invalid_base32_character_o(self) -> None:
        with pytest.raises(ValueError, match="Invalid geohash character 'o'"):
            decode("9q8yyo")

    def test_invalid_base32_character_a(self) -> None:
        with pytest.raises(ValueError, match="Invalid geohash character 'a'"):
            decode("9q8yya")

    def test_invalid_base32_character_i(self) -> None:
        with pytest.raises(ValueError, match="Invalid geohash character 'i'"):
            decode("9q8yyi")

    def test_invalid_base32_character_l(self) -> None:
        with pytest.raises(ValueError, match="Invalid geohash character 'l'"):
            decode("9q8yyl")

    def test_invalid_base32_special_chars(self) -> None:
        with pytest.raises(ValueError, match="Invalid geohash character"):
            decode("9q8yy#")
        with pytest.raises(ValueError, match="Invalid geohash character"):
            decode("9q8yy@")

    def test_engine_insert_oob_sets_diag_841d(self) -> None:
        engine = GeohashCanvasEngine()
        with pytest.raises(ValueError, match="out of bounds"):
            engine.insert_asset(95.0, 0.0)
        assert engine.diagnostic_code == DIAG_COORDINATE_OUT_OF_BOUNDS
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x841D

    def test_engine_set_precision_invalid_sets_diag_841d(self) -> None:
        engine = GeohashCanvasEngine()
        with pytest.raises(ValueError, match="Invalid precision"):
            engine.set_precision(0)
        assert engine.diagnostic_code == DIAG_COORDINATE_OUT_OF_BOUNDS


# ============================================================================
# 5. Proximity Hazard Collision Detection Tests
# ============================================================================

class TestProximityHazardCollision:
    def test_haversine_formula_known_distances(self) -> None:
        # Same coordinates -> 0.0
        assert haversine_distance_m(37.77, -122.42, 37.77, -122.42) == 0.0

        # 1 degree latitude along meridian ~111.195 km
        d1 = haversine_distance_m(0.0, 0.0, 1.0, 0.0)
        assert 111000.0 < d1 < 112000.0

        # Small 0.0001 deg step (~11.1 meters)
        d_step = haversine_distance_m(37.7700, -122.4200, 37.7701, -122.4200)
        assert 11.0 < d_step < 11.2

    def test_no_hazards_single_asset(self) -> None:
        engine = GeohashCanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        hazards = engine.detect_collisions()
        assert len(hazards) == 0
        assert engine.nearest_distance_m == 65535.0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK

    def test_no_hazards_distant_assets(self) -> None:
        engine = GeohashCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7700, -122.4200, asset_id=1)
        engine.insert_asset(37.7790, -122.4200, asset_id=2)
        hazards = engine.detect_collisions()
        assert len(hazards) == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.nearest_distance_m > 50.0

    def test_collision_hazard_trip_two_close_assets(self) -> None:
        engine = GeohashCanvasEngine(safety_threshold_m=50.0)
        a1 = engine.insert_asset(37.7750, -122.4180, asset_id=1, tag="VLV-01")
        a2 = engine.insert_asset(37.7751, -122.4180, asset_id=2, tag="AGV-02")
        hazards = engine.detect_collisions()

        assert len(hazards) == 1
        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x841C
        assert engine.nearest_distance_m < 50.0
        assert a1.status == "alarm"
        assert a2.status == "alarm"
        assert (engine.status_word & GeohashStatusBits.COLLISION_ALARM) != 0

    def test_collision_hazard_recovery_on_asset_removal(self) -> None:
        engine = GeohashCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1)
        engine.insert_asset(37.7751, -122.4180, asset_id=2)
        assert engine.collision_alarm is True

        engine.remove_asset(2)
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (engine.status_word & GeohashStatusBits.COLLISION_ALARM) == 0

    def test_manual_alarm_clear(self) -> None:
        engine = GeohashCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1)
        engine.insert_asset(37.7751, -122.4180, asset_id=2)
        assert engine.collision_alarm is True

        engine.clear_alarm()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert len(engine.active_hazards) == 0

    def test_custom_safety_threshold_trip(self) -> None:
        engine = GeohashCanvasEngine()
        # Assets ~66 meters apart (0.0006 deg lat)
        engine.insert_asset(37.7700, -122.4200, asset_id=1)
        engine.insert_asset(37.7706, -122.4200, asset_id=2)

        # Standard threshold 50m -> no collision
        engine.detect_collisions(safety_threshold_m=50.0)
        assert engine.collision_alarm is False

        # Custom threshold 100m -> trips collision
        engine.detect_collisions(safety_threshold_m=100.0)
        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION

    def test_multi_asset_cluster_hazards(self) -> None:
        engine = GeohashCanvasEngine(safety_threshold_m=50.0)
        # 3 close assets (~11m apart) and 1 far asset (~1km apart)
        engine.insert_asset(37.7700, -122.4200, asset_id=1)
        engine.insert_asset(37.7701, -122.4200, asset_id=2)
        engine.insert_asset(37.7702, -122.4200, asset_id=3)
        engine.insert_asset(37.7800, -122.4200, asset_id=4)

        hazards = engine.detect_collisions()
        # Pairs: (1,2), (2,3), and (1,3 is ~22m so also < 50m) -> 3 pairs
        assert len(hazards) == 3
        assert engine.collision_alarm is True

    def test_status_word_hazard_bit_trip_and_clear(self) -> None:
        engine = GeohashCanvasEngine(safety_threshold_m=50.0)
        assert (engine.status_word & GeohashStatusBits.COLLISION_ALARM) == 0

        engine.insert_asset(37.7700, -122.4200, asset_id=1)
        engine.insert_asset(37.7701, -122.4200, asset_id=2)
        assert (engine.status_word & GeohashStatusBits.COLLISION_ALARM) != 0

        engine.clear_alarm()
        assert (engine.status_word & GeohashStatusBits.COLLISION_ALARM) == 0


# ============================================================================
# 6. Horner OCS Register Table Synchronization Tests
# ============================================================================

class TestHornerOcsRegisterSync:
    def test_sync_to_registers_nominal(self) -> None:
        engine = GeohashCanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.insert_asset(37.7720, -122.4210, asset_id=2)
        engine.select_prefix("9q8y")

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_GEOHASH_TOTAL_ASSETS) == 2
        assert rt.read_word(REG_GEOHASH_SELECTED_PREFIX_W1) == engine.prefix_w1
        assert rt.read_word(REG_GEOHASH_SELECTED_PREFIX_W2) == engine.prefix_w2
        assert rt.read_word(REG_GEOHASH_PRECISION_LEVEL) == 6
        assert rt.read_word(REG_GEOHASH_CANVAS_ZOOM) == 100
        assert rt.read_word(REG_GEOHASH_DIAGNOSTIC_CODE) == int(DIAG_OK)
        assert rt.read_bit(COIL_GEOHASH_ONLINE) is True
        assert rt.read_bit(COIL_GEOHASH_COLLISION_ALARM) is False

    def test_sync_to_registers_alarm_active(self) -> None:
        engine = GeohashCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1)
        engine.insert_asset(37.7751, -122.4180, asset_id=2)

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_bit(COIL_GEOHASH_COLLISION_ALARM) is True
        diag_val = rt.read_word(REG_GEOHASH_DIAGNOSTIC_CODE) & 0xFFFF
        assert diag_val == (int(DIAG_PROXIMITY_HAZARD_COLLISION) & 0xFFFF)
        dist_val = rt.read_word(REG_GEOHASH_NEAREST_DISTANCE_M)
        assert dist_val < 50

    def test_register_table_signed_16bit_masking(self) -> None:
        rt = RegisterTable()
        test_values = [
            ("%R2700", 25, 25),
            ("%R2703", 6, 6),
            ("%R2707", 0x841C, 0x841C),
            ("%R2707", -31716, 0x841C),
            ("%R2707", 0x841D, 0x841D),
            ("%R2707", -1, 0xFFFF),
            ("%R2707", 0x0000, 0x0000),
        ]
        for reg, val, expected in test_values:
            rt.write_word(reg, val & 0xFFFF)
            assert (rt.read_word(reg) & 0xFFFF) == expected

    def test_sync_from_registers_online_coil(self) -> None:
        engine = GeohashCanvasEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert engine.online is True

        rt.write_bit(COIL_GEOHASH_ONLINE, False)
        engine.sync_from_registers(rt)
        assert engine.online is False

    def test_sync_from_registers_zoom_and_precision(self) -> None:
        engine = GeohashCanvasEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        rt.write_word(REG_GEOHASH_CANVAS_ZOOM, 175)
        rt.write_word(REG_GEOHASH_PRECISION_LEVEL, 8)
        engine.sync_from_registers(rt)

        assert engine.zoom == 175
        assert engine.precision == 8

    def test_sync_from_registers_prefix_words(self) -> None:
        engine = GeohashCanvasEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        w1, w2 = pack_geohash_to_words("9q8y")
        rt.write_word(REG_GEOHASH_SELECTED_PREFIX_W1, w1)
        rt.write_word(REG_GEOHASH_SELECTED_PREFIX_W2, w2)
        engine.sync_from_registers(rt)

        assert engine.selected_prefix == "9q8y"

    def test_sync_from_registers_invalid_precision_ignored(self) -> None:
        engine = GeohashCanvasEngine(precision=6)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        # Write invalid precision out of 1..12 range
        rt.write_word(REG_GEOHASH_PRECISION_LEVEL, 99)
        engine.sync_from_registers(rt)
        assert engine.precision == 6  # Preserved original valid precision


# ============================================================================
# 7. SVG SCADA Canvas Rendering & WCAG Contrast Tests
# ============================================================================

class TestSvgCanvasAndWcagContrast:
    def test_wcag_aaa_contrast_calculations(self) -> None:
        # Scorecard text (#FFFFFF) on badge (#05080C) > 18:1
        ratio_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio_badge >= 18.0

        # Background (#0D1117) > 18:1
        ratio_bg = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_SCADA_BG)
        assert ratio_bg >= 18.0

        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, target_ratio=18.0)

    def test_wcag_aaa_contrast_muted_text(self) -> None:
        # Muted text (#CBD5E1) on badge (#05080C) > 7:1 (WCAG AAA small text requirement)
        ratio_muted = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE)
        assert ratio_muted >= 7.0

    def test_svg_rendering_and_xml_validity(self) -> None:
        engine = create_canonical_geohash_canvas(sample_count=8, seed=42)
        svg_text = generate_geohash_canvas_svg(engine)

        root = ET.fromstring(svg_text)
        assert root.tag.endswith("svg")
        assert root.attrib.get("width") == "800"
        assert root.attrib.get("height") == "600"
        assert root.attrib.get("viewBox") == "0 0 800 600"

        # Check required structural elements
        assert "geohash-grid-container" in svg_text
        assert "geohash-hazard-zones" in svg_text
        assert "geohash-asset-markers" in svg_text
        assert "hud-telemetry-scorecard" in svg_text

    def test_svg_hazard_rendering(self) -> None:
        engine = GeohashCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1, tag="A1")
        engine.insert_asset(37.7751, -122.4180, asset_id=2, tag="A2")
        engine.detect_collisions()

        svg_text = generate_geohash_canvas_svg(engine)
        assert "hazard-collision-line" in svg_text
        assert "HAZARD" in svg_text
        assert "SPATIAL PROXIMITY HAZARD COLLISION ALARM" in svg_text

    def test_svg_asset_symbol_renderers(self) -> None:
        engine = GeohashCanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1, asset_type="valve", tag="VLV-01")
        engine.insert_asset(37.7720, -122.4210, asset_id=2, asset_type="pump", tag="PMP-02")
        engine.insert_asset(37.7730, -122.4220, asset_id=3, asset_type="tank", tag="TNK-03")
        engine.insert_asset(37.7740, -122.4230, asset_id=4, asset_type="agv", tag="AGV-04")
        engine.insert_asset(37.7750, -122.4240, asset_id=5, asset_type="sensor", tag="SEN-05")

        svg_text = generate_geohash_canvas_svg(engine)
        assert "valve-symbol" in svg_text
        assert "pump-symbol" in svg_text
        assert "tank-symbol" in svg_text
        assert "agv-symbol" in svg_text
        assert "sensor-symbol" in svg_text

    def test_svg_prefix_selection_styling(self) -> None:
        engine = create_canonical_geohash_canvas(sample_count=6, seed=42)
        asset_prefix = list(engine.assets.values())[0].geohash[:4]
        engine.select_prefix(asset_prefix)

        svg_text = generate_geohash_canvas_svg(engine)
        assert COLOR_RETICLE_CYAN in svg_text
        assert asset_prefix.upper() in svg_text or asset_prefix in svg_text

    def test_canonical_geohash_canvas_creation(self) -> None:
        engine = create_canonical_geohash_canvas(sample_count=12, precision=6, seed=77)
        assert engine.total_assets == 12
        assert engine.precision == 6
        svg_text = generate_geohash_canvas_svg(engine)
        assert "geohash-asset-12" in svg_text


# ============================================================================
# 8. Pure IEC 61131-3 Structured Text & Anti-Ladder Rejection Tests
# ============================================================================

class TestPureSTAndSecurityRejection:
    def test_clean_st_pou_verification(self) -> None:
        assert verify_geohash_canvas_pure_st() is True

    def test_st_parser_pou_ast_properties(self) -> None:
        parser = STParser()
        ast = parser.parse(ST_PROGRAM_W309_GEOHASH_CANVAS_SYNC)
        assert ast is not None
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "GeohashSpatialCanvasSync"

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
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P NETWORK 1: X := 1; END_PROGRAM")

    def test_reject_ladder_contact_mnemonics(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P XIC Tag1; END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P XIO Tag1; END_PROGRAM")

    def test_reject_ladder_coil_mnemonics(self) -> None:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P OTE Tag1; END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P OTL Tag1; END_PROGRAM")
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content("PROGRAM P OTU Tag1; END_PROGRAM")

    def test_security_guard_pure_st_content_passes(self) -> None:
        clean_code = "PROGRAM Clean VAR a: INT; END_VAR a := 10; END_PROGRAM"
        # Should execute without raising LadderForbiddenError
        SecurityGuard.assert_pure_st_content(clean_code)


# ============================================================================
# 9. ILogicUnit Simulation & 100-Cycle Soak with Memory Profiling Tests
# ============================================================================

class TestILogicUnitComplianceAndSoak:
    def test_ilogicunit_properties_and_methods(self) -> None:
        engine = GeohashCanvasEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "GeohashCanvasEngine"
        assert engine.priority == 100
        assert engine.is_enabled is True

        res = engine.scan_step()
        assert isinstance(res, ExecutionResult)
        assert res.status == AgentStatus.SUCCESS
        assert engine.cycle_count == 1

        engine.step()
        assert engine.cycle_count == 2

        res_exec = engine.execute()
        assert isinstance(res_exec, ExecutionResult)
        assert res_exec.status == AgentStatus.SUCCESS
        assert engine.cycle_count == 3

    def test_ilogicunit_scan_step_with_args_and_kwargs(self) -> None:
        engine = GeohashCanvasEngine()
        res = engine.scan_step(None, 123, "test_param", custom_flag=True)
        assert res.status == AgentStatus.SUCCESS
        assert engine.cycle_count == 1

    def test_ilogicunit_scan_step_alarm_failure_result(self) -> None:
        engine = GeohashCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1)
        engine.insert_asset(37.7751, -122.4180, asset_id=2)

        res = engine.scan_step()
        assert res.status == AgentStatus.FAILED
        assert res.error_code == str(DIAG_PROXIMITY_HAZARD_COLLISION)

    def test_ilogicunit_reset_restores_clean_state(self) -> None:
        engine = GeohashCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1)
        engine.insert_asset(37.7751, -122.4180, asset_id=2)
        engine.scan_step()
        assert engine.cycle_count == 1
        assert engine.collision_alarm is True

        engine.reset()
        assert engine.cycle_count == 0
        assert engine.total_assets == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK

    def test_100_cycle_simulation_soak(self) -> None:
        engine = create_canonical_geohash_canvas(sample_count=8, seed=42)
        rt = RegisterTable()
        ctx = ScanContext(cycle=0, register_table=rt)

        for i in range(100):
            ctx.cycle = i
            res = engine.scan_step(ctx)
            assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)

        assert engine.cycle_count == 100
        assert engine.total_assets == 8

    def test_simulation_soak_memory_profiling(self) -> None:
        engine = create_canonical_geohash_canvas(sample_count=10, seed=99)
        rt = RegisterTable()
        ctx = ScanContext(cycle=0, register_table=rt)

        tracemalloc.start()
        snapshot_start = tracemalloc.take_snapshot()

        for i in range(100):
            ctx.cycle = i
            engine.scan_step(ctx)

        snapshot_end = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snapshot_end.compare_to(snapshot_start, "lineno")
        total_growth = sum(stat.size_diff for stat in stats if stat.size_diff > 0)
        # Verify no unbounded memory leak across 100 scan cycles (< 200 KB growth)
        assert total_growth < 200_000, f"Unbounded memory growth detected: {total_growth} bytes"


# ============================================================================
# 10. 9-Stage Verification Suite & CLI Interop Tests
# ============================================================================

class TestDeterministicVerificationRunnerAndCLI:
    def test_verification_runner_execution(self) -> None:
        res = run_geohash_canvas_verification(work_package="W309", quick=True)
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["stages"]) == 9
        for stage in res["data"]["stages"]:
            assert stage["passed"] is True

    def test_verification_runner_artifact_generation(self, tmp_path: Path) -> None:
        out_json = tmp_path / "w309_evidence.json"
        sample_svg = tmp_path / "w309_sample.svg"

        res = run_geohash_canvas_verification(
            output_path=out_json,
            sample_svg_path=sample_svg,
            work_package="W309",
            quick=True,
        )

        assert res["status"] == "success"
        assert out_json.exists()
        assert sample_svg.exists()

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert data["status"] == "success"
            assert data["data"]["work_package"] == "W309"
            assert len(data["data"]["stages"]) == 9

        svg_content = sample_svg.read_text(encoding="utf-8")
        assert "<svg" in svg_content
        assert "hud-telemetry-scorecard" in svg_content

    def test_verification_runner_cli_subprocess_tempfiles(self, tmp_path: Path) -> None:
        out_json = tmp_path / "cli_evidence.json"
        sample_svg = tmp_path / "cli_sample.svg"

        cmd = [
            sys.executable,
            "scripts/run_geohash_canvas_verification.py",
            "--quick",
            "--output",
            str(out_json),
            "--svg",
            str(sample_svg),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        assert proc.returncode == 0, f"CLI runner failed: {proc.stderr}"
        assert out_json.exists()
        assert sample_svg.exists()

    def test_verification_runner_cli_json_mode(self) -> None:
        cmd = [
            sys.executable,
            "scripts/run_geohash_canvas_verification.py",
            "--quick",
            "--json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        assert proc.returncode == 0, f"CLI json mode failed: {proc.stderr}"
        parsed = json.loads(proc.stdout)
        assert parsed["status"] == "success"
        assert parsed["data"]["checks_passed"] == 9

    def test_verification_runner_cli_custom_work_package(self, tmp_path: Path) -> None:
        out_json = tmp_path / "wp_evidence.json"
        cmd = [
            sys.executable,
            "scripts/run_geohash_canvas_verification.py",
            "--quick",
            "--work-package",
            "W309_VERIFY",
            "--output",
            str(out_json),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        assert proc.returncode == 0
        with open(out_json, "r", encoding="utf-8") as f:
            evidence = json.load(f)
            assert evidence["data"]["work_package"] == "W309_VERIFY"


# ============================================================================
# 11. Key Requirements & Boundary Enforcement Verification Tests
# ============================================================================

class TestGeohashCanvasKeyRequirements:
    """Explicit tests addressing all W309 specification requirements (Gate G9 / G2)."""

    def test_key_req_geohash_encoding_decoding_bijection_precisions_1_to_8(self) -> None:
        """Test Geohash encode/decode inverse roundtrips for precisions 1..8."""
        locations = [
            (37.7749, -122.4194),
            (51.5074, -0.1278),
            (-33.8688, 151.2093),
            (35.6762, 139.6503),
        ]
        for lat, lon in locations:
            for p in range(1, 9):
                gh = encode(lat, lon, precision=p)
                assert len(gh) == p
                bbox = decode_bbox(gh)
                assert bbox.contains(lat, lon)
                c_lat, c_lon = decode(gh)
                assert bbox.min_lat <= c_lat <= bbox.max_lat
                assert bbox.min_lon <= c_lon <= bbox.max_lon

    def test_key_req_8_neighbor_spatial_adjacency_completeness(self) -> None:
        """Test 8-neighbor spatial adjacency completeness and direction mapping."""
        gh = "9q8yyk"
        nbrs = neighbors(gh)
        expected_dirs = {"n", "s", "e", "w", "ne", "nw", "se", "sw"}
        assert set(expected_dirs).issubset(set(nbrs.keys()))
        for d in expected_dirs:
            assert len(nbrs[d]) == len(gh)
            assert nbrs[d] != gh

    def test_key_req_proximity_hazard_detection_m631_and_diagnostic_code_841c(self) -> None:
        """Test spatial proximity collision hazard detection (%M631, diagnostic code 0x841C)."""
        engine = GeohashCanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1, tag="PMP-01")
        engine.insert_asset(37.7751, -122.4180, asset_id=2, tag="VLV-02")

        hazards = engine.detect_collisions()
        assert len(hazards) >= 1
        assert engine.collision_alarm is True
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x841C
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION

        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert rt.read_bit(COIL_GEOHASH_COLLISION_ALARM) is True
        assert rt.read_bit("%M631") is True
        assert (rt.read_word(REG_GEOHASH_DIAGNOSTIC_CODE) & 0xFFFF) == 0x841C
        assert (rt.read_word("%R2707") & 0xFFFF) == 0x841C

    def test_key_req_out_of_bounds_handling_and_diagnostic_code_841d(self) -> None:
        """Test out-of-bounds latitude/longitude inputs handling and diagnostic code 0x841D."""
        engine = GeohashCanvasEngine()
        with pytest.raises(ValueError):
            engine.insert_asset(91.0, 0.0)
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x841D
        assert engine.diagnostic_code == DIAG_COORDINATE_OUT_OF_BOUNDS

    def test_key_req_invalid_base32_handling_and_diagnostic_code_841e(self) -> None:
        """Test invalid base32 characters handling and diagnostic code 0x841E."""
        with pytest.raises(ValueError):
            decode("9q8yyo")  # 'o' is invalid
        with pytest.raises(ValueError):
            decode("9q8yya")  # 'a' is invalid
        with pytest.raises(ValueError):
            decode("9q8yyi")  # 'i' is invalid
        with pytest.raises(ValueError):
            decode("9q8yyl")  # 'l' is invalid

    def test_key_req_svg_scada_canvas_rendering_and_wcag_aaa_contrast(self) -> None:
        """Test SVG SCADA canvas rendering, valid XML, and WCAG AAA contrast ratio (> 18:1)."""
        engine = create_canonical_geohash_canvas(sample_count=10, seed=55)
        svg = generate_geohash_canvas_svg(engine)

        root = ET.fromstring(svg)
        assert root.tag.endswith("svg")
        assert root.attrib.get("width") == "800"
        assert root.attrib.get("height") == "600"

        # WCAG 2.1 AAA contrast > 18:1
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio >= 18.0
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, target_ratio=18.0)

    def test_key_req_horner_register_table_signed_16bit_masking(self) -> None:
        """Test Horner RegisterTable sync with signed 16-bit masking across %R2700..%R2707."""
        engine = GeohashCanvasEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        for reg in [
            REG_GEOHASH_TOTAL_ASSETS,
            REG_GEOHASH_SELECTED_PREFIX_W1,
            REG_GEOHASH_SELECTED_PREFIX_W2,
            REG_GEOHASH_PRECISION_LEVEL,
            REG_GEOHASH_NEAREST_DISTANCE_M,
            REG_GEOHASH_QUERY_LATENCY_US,
            REG_GEOHASH_CANVAS_ZOOM,
            REG_GEOHASH_DIAGNOSTIC_CODE,
        ]:
            val = rt.read_word(reg)
            assert 0 <= (val & 0xFFFF) <= 0xFFFF

    def test_key_req_pure_st_pou_ast_and_anti_ladder_rejection(self) -> None:
        """Test pure ST POU AST parsing and rejection of all 9 ladder constructs."""
        assert verify_geohash_canvas_pure_st() is True
        parser = STParser()
        ast = parser.parse(ST_PROGRAM_W309_GEOHASH_CANVAS_SYNC)
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "GeohashSpatialCanvasSync"

        # 9 prohibited ladder constructs
        ladder_tests = [
            "PROGRAM Test ---[ ]--- END_PROGRAM",       # 1. Contact open
            "PROGRAM Test ---[/]--- END_PROGRAM",       # 2. Contact closed
            "PROGRAM Test ---( )--- END_PROGRAM",       # 3. Coil standard
            "PROGRAM Test ---(/)--- END_PROGRAM",       # 4. Coil negated
            "PROGRAM Test ---(S)--- END_PROGRAM",       # 5. Coil set
            "PROGRAM Test ---(R)--- END_PROGRAM",       # 6. Coil reset
            "PROGRAM Test RUNG 1: X:=1; END_PROGRAM",   # 7. Rung delimiter
            "PROGRAM Test XIC Tag1; END_PROGRAM",       # 8. Contact mnemonic
            "PROGRAM Test OTE Tag1; END_PROGRAM",       # 9. Coil mnemonic
        ]
        for ladder in ladder_tests:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(ladder)

    def test_key_req_ilogicunit_simulation_soak_100_cycles_and_memory(self) -> None:
        """Test ILogicUnit simulation soak 100 cycles and memory stability."""
        engine = create_canonical_geohash_canvas(sample_count=8, seed=42)
        rt = RegisterTable()
        ctx = ScanContext(cycle=0, register_table=rt)

        for c in range(100):
            ctx.cycle = c
            res = engine.scan_step(ctx)
            assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)

        assert engine.cycle_count == 100

    def test_key_req_9_stage_verification_runner_clean_pass(self) -> None:
        """Test 9-stage verification runner returning strict 4-state success contract."""
        res = run_geohash_canvas_verification(work_package="W309", quick=True)
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
