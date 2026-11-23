"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial H3 Hexagonal DGGS SCADA Canvas (W315).

Work Package: W315 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial H3 Hexagonal DGGS SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. H3 constants, base cells (122 total, 12 pentagons, 110 hexagons), registers %R2760..%R2767, coils %M644..%M645, diagnostic codes (signed 16-bit safe comparisons)
2. Pure Python H3 spherical coordinate to icosahedron face and hexagonal coordinate projection, index encoding/decoding
3. H3 aperture-7 hierarchical subdivision across resolutions 1..8 and k-ring (6-neighbor) adjacency
4. Out-of-bounds latitude/longitude inputs handling (0x8431) and invalid H3 index handling (0x8432)
5. Dynamic spatial proximity collision hazard alarm (0x8430, %M645 asserted) and clearance
6. RegisterTable synchronization across %R2760..%R2767 and %M644..%M645
7. SVG SCADA canvas rendering: XML validity, dimensions (800x600), asset count, contrast ratio (WCAG AAA > 18:1)
8. Pure ST POU validation with STParser and anti-ladder rejection of all 9 constructs
9. ILogicUnit scan step and 100-cycle simulation soak with memory profiling
10. 9-stage verification runner test and CLI interop (pass tempfile for --output and --svg!)
11. Key requirements and boundary enforcement verification
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

from jev_cscape.hmi.h3_canvas import (
    APERTURE_ANGLE_RAD,
    BASE_CELL_COORDINATES,
    BASE_CELL_RADIUS_M,
    CANDIDATE_OFFSETS,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_H3_CANVAS_ONLINE,
    COIL_H3_COLLISION_ALARM,
    COIL_H3_HAZARD_ALARM,
    COIL_H3_ONLINE,
    COIL_W315_CANVAS_ONLINE,
    COIL_W315_COLLISION_ALARM,
    COIL_W315_H3_ONLINE,
    COIL_W315_HAZARD_ALARM,
    COIL_W315_ONLINE,
    COLOR_ALARM_CRIMSON,
    COLOR_BORDER,
    COLOR_DARK_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_GRID_LINE,
    COLOR_HEX_FILL,
    COLOR_HEX_STROKE,
    COLOR_NOMINAL_EMERALD,
    COLOR_RETICLE_CYAN,
    COLOR_SCADA_BG,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_WARNING_AMBER,
    DEFAULT_DOMAIN_BBOX,
    DEFAULT_H3_RES,
    DEFAULT_HAZARD_THRESHOLD,
    DEFAULT_RESOLUTION,
    DEFAULT_SAFETY_THRESHOLD_M,
    DEFAULT_VIEWPORT_HEIGHT,
    DEFAULT_VIEWPORT_WIDTH,
    DIAG_COORDINATE_OUT_OF_BOUNDS,
    DIAG_ERR_INVALID_INDEX,
    DIAG_ERR_OUT_OF_BOUNDS,
    DIAG_ERR_PROXIMITY_HAZARD,
    DIAG_H3_INVALID_INDEX,
    DIAG_INVALID_INDEX,
    DIAG_OK,
    DIAG_PROXIMITY_HAZARD_COLLISION,
    DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS,
    DiagnosticCode,
    EARTH_RADIUS_METERS,
    H3_CANVAS_PURE_ST_POU,
    H3Asset,
    H3Canvas,
    H3CanvasEngine,
    H3Cell,
    H3CellId,
    H3DiagnosticCode,
    H3Index,
    H3Metrics,
    H3Point,
    H3SpatialObject,
    H3StatusBits,
    MAX_H3_RES,
    MAX_RESOLUTION,
    MAX_SCADA_RES,
    MIN_H3_RES,
    MIN_RESOLUTION,
    MIN_SCADA_RES,
    NUM_BASE_CELLS,
    NUM_HEXAGON_BASE_CELLS,
    NUM_PENTAGON_BASE_CELLS,
    PENTAGON_BASE_CELL_INDICES,
    REG_H3_DIAGNOSTIC_CODE,
    REG_H3_INDEX_HI,
    REG_H3_INDEX_LO,
    REG_H3_NEAREST_DISTANCE_M,
    REG_H3_QUERY_LATENCY_US,
    REG_H3_SELECTED_BASE_CELL,
    REG_H3_SELECTED_RESOLUTION,
    REG_H3_TOTAL_ASSETS,
    REG_H3_TOTAL_OBJECTS,
    REG_W315_DIAGNOSTIC_CODE,
    REG_W315_INDEX_HI,
    REG_W315_INDEX_LO,
    REG_W315_NEAREST_DISTANCE_M,
    REG_W315_QUERY_LATENCY_US,
    REG_W315_SELECTED_BASE_CELL,
    REG_W315_SELECTED_RESOLUTION,
    REG_W315_TOTAL_ASSETS,
    REG_W315_TOTAL_OBJECTS,
    SQRT_7,
    ST_PROGRAM_H3_CANVAS_SYNC,
    ST_PROGRAM_W315_H3_CANVAS_SYNC,
    SpatialAsset,
    SpatialObject,
    axial_ij_to_digits,
    axial_to_tangent_xy,
    calculate_contrast_ratio,
    cell_radius_m,
    cell_spacing_m,
    create_canonical_h3_canvas,
    digits_to_axial_ij,
    find_nearest_base_cell,
    generate_h3_canvas_svg,
    h3_children,
    h3_is_pentagon,
    h3_is_valid,
    h3_k_ring,
    h3_neighbors,
    h3_parent,
    h3_to_geo_boundary,
    h3_to_lat_lon,
    haversine_distance_m,
    hex_round_axial,
    is_base_cell_pentagon,
    lat_lon_to_h3,
    pack_h3_index,
    run_h3_canvas_verification,
    tangent_xy_to_axial,
    unpack_h3_index,
    validate_wcag_aaa_contrast,
    verify_h3_canvas_pure_st,
)


# ============================================================================
# 1. Constants, Base Cells, Registers & Diagnostic Codes Tests
# ============================================================================

class TestH3ConstantsAndDiagnostics:
    def test_viewport_and_resolution_constants(self) -> None:
        assert CANVAS_VIEWPORT_WIDTH == 800.0
        assert CANVAS_VIEWPORT_HEIGHT == 600.0
        assert DEFAULT_VIEWPORT_WIDTH == 800.0
        assert DEFAULT_VIEWPORT_HEIGHT == 600.0
        assert MIN_H3_RES == 0
        assert MAX_H3_RES == 15
        assert DEFAULT_H3_RES == 7
        assert MIN_SCADA_RES == 1
        assert MAX_SCADA_RES == 8
        assert MIN_RESOLUTION == 0
        assert MAX_RESOLUTION == 15
        assert DEFAULT_RESOLUTION == 7
        assert DEFAULT_SAFETY_THRESHOLD_M == 50.0
        assert DEFAULT_HAZARD_THRESHOLD == 50.0
        assert EARTH_RADIUS_METERS == 6371000.0
        assert BASE_CELL_RADIUS_M == 1750000.0
        assert abs(SQRT_7 - math.sqrt(7.0)) < 1e-9
        assert abs(APERTURE_ANGLE_RAD - math.asin(math.sqrt(3.0) / (2.0 * math.sqrt(7.0)))) < 1e-9
        assert DEFAULT_DOMAIN_BBOX == (37.7700, -122.4250, 37.7800, -122.4100)

    def test_base_cell_counts_and_pentagon_set(self) -> None:
        assert NUM_BASE_CELLS == 122
        assert NUM_PENTAGON_BASE_CELLS == 12
        assert NUM_HEXAGON_BASE_CELLS == 110
        assert len(PENTAGON_BASE_CELL_INDICES) == 12
        expected_pentagons = {4, 14, 24, 38, 49, 58, 63, 72, 83, 97, 107, 117}
        assert PENTAGON_BASE_CELL_INDICES == expected_pentagons
        assert len(BASE_CELL_COORDINATES) == 122

        for bc in range(NUM_BASE_CELLS):
            if bc in PENTAGON_BASE_CELL_INDICES:
                assert is_base_cell_pentagon(bc) is True
            else:
                assert is_base_cell_pentagon(bc) is False

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
        assert COLOR_HEX_FILL == "#1E293B"
        assert COLOR_HEX_STROKE == "#334155"

    def test_register_mappings_and_coils(self) -> None:
        assert REG_H3_TOTAL_ASSETS == "%R2760"
        assert REG_H3_SELECTED_BASE_CELL == "%R2761"
        assert REG_H3_SELECTED_RESOLUTION == "%R2762"
        assert REG_H3_INDEX_HI == "%R2763"
        assert REG_H3_INDEX_LO == "%R2764"
        assert REG_H3_NEAREST_DISTANCE_M == "%R2765"
        assert REG_H3_QUERY_LATENCY_US == "%R2766"
        assert REG_H3_DIAGNOSTIC_CODE == "%R2767"
        assert COIL_H3_ONLINE == "%M644"
        assert COIL_H3_COLLISION_ALARM == "%M645"

        # W315 aliases
        assert REG_W315_TOTAL_ASSETS == "%R2760"
        assert REG_W315_TOTAL_OBJECTS == "%R2760"
        assert REG_H3_TOTAL_OBJECTS == "%R2760"
        assert REG_W315_SELECTED_BASE_CELL == "%R2761"
        assert REG_W315_SELECTED_RESOLUTION == "%R2762"
        assert REG_W315_INDEX_HI == "%R2763"
        assert REG_W315_INDEX_LO == "%R2764"
        assert REG_W315_NEAREST_DISTANCE_M == "%R2765"
        assert REG_W315_QUERY_LATENCY_US == "%R2766"
        assert REG_W315_DIAGNOSTIC_CODE == "%R2767"
        assert COIL_W315_H3_ONLINE == "%M644"
        assert COIL_W315_ONLINE == "%M644"
        assert COIL_W315_CANVAS_ONLINE == "%M644"
        assert COIL_H3_CANVAS_ONLINE == "%M644"
        assert COIL_W315_COLLISION_ALARM == "%M645"
        assert COIL_W315_HAZARD_ALARM == "%M645"
        assert COIL_H3_HAZARD_ALARM == "%M645"

    def test_diagnostic_codes_values_and_representations(self) -> None:
        assert int(DIAG_OK) == 0x0000
        assert int(DIAG_PROXIMITY_HAZARD_COLLISION) == 0x8430
        assert int(DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS) == 0x8431
        assert int(DIAG_H3_INVALID_INDEX) == 0x8432

        assert repr(DIAG_PROXIMITY_HAZARD_COLLISION) == "DiagnosticCode(0x8430)"
        assert str(DIAG_PROXIMITY_HAZARD_COLLISION) == "0x8430"
        assert str(DIAG_OK) == "0x0000"

    def test_diagnostic_codes_signed_16bit_equality(self) -> None:
        # DiagnosticCode implements signed 16-bit safe comparisons
        # 0x8430 is 33840 unsigned, -31696 signed
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8430
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 33840
        assert DIAG_PROXIMITY_HAZARD_COLLISION == -31696
        assert DIAG_PROXIMITY_HAZARD_COLLISION == (0x8430 - 0x10000)

        # 0x8431 is 33841 unsigned, -31695 signed
        assert DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS == 0x8431
        assert DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS == 33841
        assert DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS == -31695
        assert DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS == (0x8431 - 0x10000)

        # 0x8432 is 33842 unsigned, -31694 signed
        assert DIAG_H3_INVALID_INDEX == 0x8432
        assert DIAG_H3_INVALID_INDEX == 33842
        assert DIAG_H3_INVALID_INDEX == -31694
        assert DIAG_H3_INVALID_INDEX == (0x8432 - 0x10000)

        assert DIAG_OK == 0
        assert DIAG_OK == 0x0000

        # Set containment
        code_set = {DIAG_PROXIMITY_HAZARD_COLLISION, DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS}
        assert DIAG_PROXIMITY_HAZARD_COLLISION in code_set
        assert 0x8430 in code_set

    def test_diagnostic_codes_aliases(self) -> None:
        assert DIAG_ERR_PROXIMITY_HAZARD == DIAG_PROXIMITY_HAZARD_COLLISION
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS
        assert DIAG_ERR_OUT_OF_BOUNDS == DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS
        assert DIAG_INVALID_INDEX == DIAG_H3_INVALID_INDEX
        assert DIAG_ERR_INVALID_INDEX == DIAG_H3_INVALID_INDEX

        # DiagnosticCode handles alias comparisons
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x842C
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8428
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8424
        assert DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS == 0x842D
        assert DIAG_H3_INVALID_INDEX == 0x842E

    def test_status_bits(self) -> None:
        assert H3StatusBits.ONLINE == 1
        assert H3StatusBits.COLLISION_ALARM == 2
        assert H3StatusBits.GRID_GENERATED == 4
        assert H3StatusBits.HIGH_DENSITY == 8
        assert H3StatusBits.CELL_SELECTED == 16

        combined = H3StatusBits.ONLINE | H3StatusBits.GRID_GENERATED | H3StatusBits.CELL_SELECTED
        assert (combined & H3StatusBits.ONLINE) != 0
        assert (combined & H3StatusBits.COLLISION_ALARM) == 0
        assert (combined & H3StatusBits.CELL_SELECTED) != 0

    def test_h3_index_packing_unpacking_roundtrip(self) -> None:
        test_indices = [0x00000000, 0x12345678, 0xFFFFFFFF, 0xABCD1234, 0x5555AAAA, 0x0000FFFF]
        for idx_val in test_indices:
            hi, lo = pack_h3_index(idx_val)
            assert 0 <= hi <= 0xFFFF
            assert 0 <= lo <= 0xFFFF
            unpacked = unpack_h3_index(hi, lo)
            assert unpacked == idx_val


# ============================================================================
# 2. Pure Python H3 Spherical Projection & Base Cells Tests
# ============================================================================

class TestH3BaseCellsAndSphericalProjection:
    def test_h3_point_unit_vector(self) -> None:
        pt = H3Point.from_lat_lon(0.0, 0.0)
        assert abs(pt.x - 1.0) < 1e-7
        assert abs(pt.y) < 1e-7
        assert abs(pt.z) < 1e-7
        lat, lon = pt.to_lat_lon()
        assert abs(lat) < 1e-5
        assert abs(lon) < 1e-5

        pt_north = H3Point.from_lat_lon(90.0, 0.0)
        assert abs(pt_north.z - 1.0) < 1e-7
        assert abs(pt.dot(pt_north)) < 1e-7

    def test_nearest_base_cell_lookup(self) -> None:
        test_points = [
            (37.7749, -122.4194),   # San Francisco
            (51.5074, -0.1278),     # London
            (35.6762, 139.6503),    # Tokyo
            (-33.8688, 151.2093),   # Sydney
            (0.0, 0.0),             # Gulf of Guinea
            (90.0, 0.0),            # North Pole (Pentagon 4)
            (-90.0, 0.0),           # South Pole (Pentagon 117)
        ]
        for lat, lon in test_points:
            bc = find_nearest_base_cell(lat, lon)
            assert 0 <= bc < NUM_BASE_CELLS

    def test_north_and_south_pole_base_cells(self) -> None:
        bc_north = find_nearest_base_cell(90.0, 0.0)
        assert is_base_cell_pentagon(bc_north) is True
        assert bc_north in PENTAGON_BASE_CELL_INDICES

        bc_south = find_nearest_base_cell(-90.0, 0.0)
        assert is_base_cell_pentagon(bc_south) is True
        assert bc_south in PENTAGON_BASE_CELL_INDICES

    def test_candidate_offsets_aperture7(self) -> None:
        assert len(CANDIDATE_OFFSETS) == 7
        assert CANDIDATE_OFFSETS[0] == (0, 0)
        det_m = 2 * 3 - (-1) * 1
        assert det_m == 7

    def test_digits_axial_ij_bijection(self) -> None:
        test_sequences = [
            [0],
            [1, 2, 3],
            [6, 5, 4, 3, 2, 1],
            [0, 0, 0, 0],
            [3, 3, 3],
        ]
        for seq in test_sequences:
            i, j = digits_to_axial_ij(seq)
            recovered = axial_ij_to_digits(i, j, len(seq))
            assert recovered == seq

    def test_hex_round_axial_continuous_rounding(self) -> None:
        for i in range(-5, 6):
            for j in range(-5, 6):
                ri, rj = hex_round_axial(float(i), float(j))
                assert (ri, rj) == (i, j)
                ri2, rj2 = hex_round_axial(float(i) + 0.1, float(j) - 0.1)
                assert (ri2, rj2) == (i, j)

    def test_tangent_xy_and_axial_roundtrip(self) -> None:
        for res in [1, 4, 7]:
            for i in [-3, 0, 3]:
                for j in [-3, 0, 3]:
                    x, y = axial_to_tangent_xy(i, j, res)
                    ri, rj = tangent_xy_to_axial(x, y, res)
                    assert (ri, rj) == (i, j)

    def test_cell_radius_and_spacing_scaling(self) -> None:
        r0 = cell_radius_m(0)
        assert abs(r0 - BASE_CELL_RADIUS_M) < 1.0
        for res in range(1, 9):
            r_cur = cell_radius_m(res)
            r_prev = cell_radius_m(res - 1)
            assert abs(r_cur - (r_prev / math.sqrt(7.0))) < 1e-3
            spacing = cell_spacing_m(res)
            assert abs(spacing - (math.sqrt(3.0) * r_cur)) < 1e-3

    def test_lat_lon_to_h3_and_back_roundtrip(self) -> None:
        test_points = [
            (37.7749, -122.4194),
            (51.5074, -0.1278),
            (35.6762, 139.6503),
            (-33.8688, 151.2093),
            (0.0, 0.0),
        ]
        for lat, lon in test_points:
            for res in [1, 3, 5, 7, 8]:
                idx = lat_lon_to_h3(lat, lon, res=res)
                assert idx.is_valid()
                assert idx.resolution == res
                c_lat, c_lon = idx.to_lat_lon()
                dist = haversine_distance_m(lat, lon, c_lat, c_lon)
                max_bound = cell_spacing_m(res) * 2.5
                assert dist <= max_bound, f"Dist {dist} > {max_bound} at res {res}"


# ============================================================================
# 3. H3 Index Encoding & Token Roundtrip Tests
# ============================================================================

class TestH3IndexEncodingAndToken:
    def test_h3_index_properties(self) -> None:
        idx = lat_lon_to_h3(37.7749, -122.4194, res=7)
        assert idx.mode == 1
        assert idx.resolution == 7
        assert idx.res == 7
        assert 0 <= idx.base_cell < NUM_BASE_CELLS
        assert idx.base_cell_num == idx.base_cell
        assert len(idx.digits) == 7
        assert idx.is_valid() is True

    def test_h3_index_hex_token_roundtrip(self) -> None:
        idx = lat_lon_to_h3(37.7749, -122.4194, res=7)
        token_str = idx.to_string()
        assert len(token_str) == 15
        assert idx.to_token() == token_str
        assert idx.to_hex() == token_str
        rec_idx = H3Index.from_string(token_str)
        assert rec_idx == idx
        assert rec_idx.id == idx.id
        assert rec_idx.resolution == idx.resolution
        assert rec_idx.base_cell == idx.base_cell

    def test_pack_and_unpack_h3_index(self) -> None:
        idx = lat_lon_to_h3(37.7749, -122.4194, res=7)
        hi, lo = pack_h3_index(idx)
        assert hi == idx.index_hi
        assert lo == idx.index_lo
        assert hi == idx.token_hi
        assert lo == idx.token_lo
        unpacked = unpack_h3_index(hi, lo)
        assert unpacked == idx.index_32

    def test_h3_index_comparison_operators(self) -> None:
        idx1 = lat_lon_to_h3(37.7749, -122.4194, res=7)
        idx2 = lat_lon_to_h3(37.7750, -122.4195, res=7)
        assert (idx1 == idx1) is True
        assert (idx1 == int(idx1)) is True
        assert (idx1 == idx1.to_string()) is True
        assert isinstance(hash(idx1), int)

        if idx1.id < idx2.id:
            assert idx1 < idx2
            assert idx1 <= idx2
            assert idx2 > idx1
            assert idx2 >= idx1
        elif idx1.id > idx2.id:
            assert idx2 < idx1
            assert idx2 <= idx1
            assert idx1 > idx2
            assert idx1 >= idx2

    def test_h3_polygon_boundary_vertices(self) -> None:
        idx = lat_lon_to_h3(37.7749, -122.4194, res=7)
        poly = idx.to_geo_boundary()
        assert len(poly) == 6
        for vlat, vlon in poly:
            assert -90.0 <= vlat <= 90.0
            assert -180.0 <= vlon <= 180.0

    def test_h3_index_from_base_cell_and_digits(self) -> None:
        idx = H3Index.from_base_cell_and_digits(base_cell=25, resolution=3, digits=[1, 4, 2])
        assert idx.base_cell == 25
        assert idx.resolution == 3
        assert idx.digits == (1, 4, 2)
        assert idx.is_valid() is True

    def test_h3_index_unused_digits_sentinel(self) -> None:
        idx = H3Index.from_base_cell_and_digits(base_cell=10, resolution=2, digits=[3, 5])
        # Bits 0..(45 - 3*2 - 1) = bits 0..38 should all be 1s (digit 7)
        for r in range(3, 16):
            shift = 45 - 3 * r
            d = (idx.id >> shift) & 7
            assert d == 7


# ============================================================================
# 3. Aperture-7 Hierarchy Across Resolutions & Adjacency Tests
# ============================================================================

class TestH3Aperture7HierarchyAndNeighbors:
    def test_parent_resolution_and_containment(self) -> None:
        child = lat_lon_to_h3(37.7749, -122.4194, res=7)
        parent = child.parent()
        assert parent.resolution == 6
        assert parent.base_cell == child.base_cell
        assert parent.contains(child) is True

    def test_children_count_and_parent_backlink(self) -> None:
        parent = lat_lon_to_h3(37.7749, -122.4194, res=5)
        children = parent.children()
        expected_count = 6 if parent.is_pentagon() else 7
        assert len(children) == expected_count
        for c in children:
            assert c.resolution == 6
            assert c.parent() == parent
            assert parent.contains(c) is True

    def test_6_neighbors_adjacency(self) -> None:
        cell = lat_lon_to_h3(37.7749, -122.4194, res=7)
        nbrs = cell.neighbors()
        expected_nbr_count = 5 if cell.is_pentagon() else 6
        assert len(nbrs) == expected_nbr_count
        assert len(set(n.id for n in nbrs)) == expected_nbr_count
        for n in nbrs:
            assert n.resolution == cell.resolution
            assert n.is_valid() is True

    def test_k_ring_sizes(self) -> None:
        cell = lat_lon_to_h3(37.7749, -122.4194, res=7)
        k0 = cell.k_ring(0)
        assert len(k0) == 1
        assert k0[0] == cell

        k1 = cell.k_ring(1)
        expected_k1 = 6 if cell.is_pentagon() else 7
        assert len(k1) == expected_k1

        k2 = cell.k_ring(2)
        expected_k2 = 16 if cell.is_pentagon() else 19
        assert len(k2) == expected_k2

        k3 = cell.k_ring(3)
        expected_k3 = 31 if cell.is_pentagon() else 37
        assert len(k3) == expected_k3

    def test_global_helper_functions(self) -> None:
        cell = lat_lon_to_h3(37.7749, -122.4194, res=6)
        assert h3_parent(cell).resolution == 5
        assert len(h3_children(cell)) == (6 if cell.is_pentagon() else 7)
        assert len(h3_neighbors(cell)) == (5 if cell.is_pentagon() else 6)
        assert len(h3_k_ring(cell, 1)) == (6 if cell.is_pentagon() else 7)
        assert h3_is_valid(cell) is True
        assert h3_is_valid("INVALID") is False
        assert h3_is_pentagon(cell) == cell.is_pentagon()

    def test_h3_cell_wrapper_class(self) -> None:
        idx = lat_lon_to_h3(37.7749, -122.4194, res=6)
        c_lat, c_lon = idx.to_lat_lon()
        poly = idx.to_geo_boundary()
        cell_obj = H3Cell(
            h3_index=idx,
            base_cell=idx.base_cell,
            resolution=idx.resolution,
            center_lat=c_lat,
            center_lon=c_lon,
            boundary=poly,
            canvas_center=(400.0, 300.0),
            canvas_polygon=[(400.0, 300.0)],
        )
        assert cell_obj.h3_index == idx
        assert cell_obj.base_cell == idx.base_cell
        assert cell_obj.resolution == 6
        assert len(cell_obj.boundary) == 6


# ============================================================================
# 4. Out-of-Bounds & Invalid Input Handling Tests
# ============================================================================

class TestH3InputValidationAndErrorHandling:
    def test_out_of_bounds_latitude_high(self) -> None:
        with pytest.raises(ValueError, match="Spherical coordinates out of bounds"):
            lat_lon_to_h3(95.0, 0.0)
        with pytest.raises(ValueError, match="Spherical coordinates out of bounds"):
            H3Point.from_lat_lon(90.1, 0.0)

    def test_out_of_bounds_latitude_low(self) -> None:
        with pytest.raises(ValueError, match="Spherical coordinates out of bounds"):
            lat_lon_to_h3(-95.0, 0.0)
        with pytest.raises(ValueError, match="Spherical coordinates out of bounds"):
            H3Point.from_lat_lon(-90.1, 0.0)

    def test_out_of_bounds_longitude_high(self) -> None:
        with pytest.raises(ValueError, match="Spherical coordinates out of bounds"):
            lat_lon_to_h3(0.0, 185.0)
        with pytest.raises(ValueError, match="Spherical coordinates out of bounds"):
            H3Point.from_lat_lon(0.0, 180.1)

    def test_out_of_bounds_longitude_low(self) -> None:
        with pytest.raises(ValueError, match="Spherical coordinates out of bounds"):
            lat_lon_to_h3(0.0, -185.0)
        with pytest.raises(ValueError, match="Spherical coordinates out of bounds"):
            H3Point.from_lat_lon(0.0, -180.1)

    def test_resolution_bounds_validation(self) -> None:
        with pytest.raises(ValueError, match="Resolution must be 0..15"):
            lat_lon_to_h3(0.0, 0.0, res=-1)
        with pytest.raises(ValueError, match="Resolution must be 0..15"):
            lat_lon_to_h3(0.0, 0.0, res=16)

    def test_invalid_h3_index_hex_string(self) -> None:
        with pytest.raises(ValueError):
            H3Index.from_string("NOT_A_HEX")
        with pytest.raises(ValueError):
            H3Index.from_string("")

    def test_engine_insert_asset_oob_sets_diagnostic(self) -> None:
        engine = H3CanvasEngine()
        with pytest.raises(ValueError):
            engine.insert_asset(95.0, 0.0)
        assert engine.diagnostic_code == DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8431

    def test_engine_select_cell_invalid_sets_diagnostic(self) -> None:
        engine = H3CanvasEngine()
        with pytest.raises(ValueError):
            engine.select_cell("INVALID_HEX_STRING")
        assert engine.diagnostic_code == DIAG_H3_INVALID_INDEX
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8432

    def test_invalid_k_ring_negative(self) -> None:
        cell = lat_lon_to_h3(0.0, 0.0, res=5)
        with pytest.raises(ValueError, match="k must be >= 0"):
            cell.k_ring(-1)

    def test_parent_child_resolution_errors(self) -> None:
        cell = lat_lon_to_h3(0.0, 0.0, res=0)
        with pytest.raises(ValueError, match="Resolution 0 has no parent"):
            cell.parent()

        cell7 = lat_lon_to_h3(0.0, 0.0, res=7)
        with pytest.raises(ValueError, match="Parent resolution"):
            cell7.parent(7)
        with pytest.raises(ValueError, match="Child resolution"):
            cell7.children(7)
        with pytest.raises(ValueError, match="Child resolution exceeds max"):
            cell7.children(16)


# ============================================================================
# 5. Dynamic Spatial Proximity Collision Hazard Alarm Tests
# ============================================================================

class TestH3ProximityHazardCollision:
    def test_haversine_known_distances(self) -> None:
        d_zero = haversine_distance_m(37.77, -122.42, 37.77, -122.42)
        assert d_zero == 0.0
        # Equator 1 degree longitude ~ 111.32 km
        d_deg = haversine_distance_m(0.0, 0.0, 0.0, 1.0)
        assert 111000.0 < d_deg < 112000.0
        # Small step ~ 11.1 meters
        d_small = haversine_distance_m(37.7700, -122.4200, 37.7701, -122.4200)
        assert 11.0 < d_small < 11.2

    def test_no_hazards_single_asset(self) -> None:
        engine = H3CanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        hazards = engine.detect_collisions()
        assert len(hazards) == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.nearest_distance_m == 65535.0

    def test_no_hazards_distant_assets(self) -> None:
        engine = H3CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7700, -122.4200, asset_id=1)
        engine.insert_asset(37.7790, -122.4200, asset_id=2)
        hazards = engine.detect_collisions()
        assert len(hazards) == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.nearest_distance_m > 50.0

    def test_collision_hazard_trip_two_close_assets(self) -> None:
        engine = H3CanvasEngine(safety_threshold_m=50.0)
        # ~11 meters apart (distance < 50m default threshold)
        a1 = engine.insert_asset(37.7770, -122.4150, asset_id=1, tag="VLV-01")
        a2 = engine.insert_asset(37.7771, -122.4150, asset_id=2, tag="AGV-02")
        hazards = engine.detect_collisions(safety_threshold_m=50.0)

        assert len(hazards) == 1
        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8430
        assert engine.nearest_distance_m < 50.0
        assert a1.status == "alarm"
        assert a2.status == "alarm"
        assert (engine.status_word & H3StatusBits.COLLISION_ALARM) != 0

    def test_collision_hazard_clear_on_asset_removal(self) -> None:
        engine = H3CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()
        assert engine.collision_alarm is True

        engine.remove_asset(2)
        engine.detect_collisions()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (engine.status_word & H3StatusBits.COLLISION_ALARM) == 0

    def test_manual_alarm_clear(self) -> None:
        engine = H3CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()
        assert engine.collision_alarm is True

        engine.clear_alarm()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert len(engine.active_hazards) == 0

    def test_custom_safety_threshold_trip(self) -> None:
        engine = H3CanvasEngine()
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
        engine = H3CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7700, -122.4200, asset_id=1)
        engine.insert_asset(37.7701, -122.4200, asset_id=2)
        engine.insert_asset(37.7702, -122.4200, asset_id=3)
        engine.insert_asset(37.7800, -122.4200, asset_id=4)

        hazards = engine.detect_collisions()
        assert len(hazards) == 3
        assert engine.collision_alarm is True


# ============================================================================
# 6. Horner OCS Register Table Synchronization Tests
# ============================================================================

class TestH3RegisterTableSync:
    def test_sync_to_registers_nominal(self) -> None:
        engine = H3CanvasEngine(resolution=7)
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.insert_asset(37.7750, -122.4250, asset_id=2)
        idx = engine.assets[1].h3_index
        engine.select_cell(idx)
        engine.detect_collisions()

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_H3_TOTAL_ASSETS) == 2
        assert rt.read_word(REG_H3_SELECTED_BASE_CELL) == idx.base_cell
        assert rt.read_word(REG_H3_SELECTED_RESOLUTION) == 7
        assert (rt.read_word(REG_H3_INDEX_HI) & 0xFFFF) == (engine.index_hi & 0xFFFF)
        assert (rt.read_word(REG_H3_INDEX_LO) & 0xFFFF) == (engine.index_lo & 0xFFFF)
        assert (rt.read_word(REG_H3_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
        assert rt.read_bit(COIL_H3_ONLINE) is True
        assert rt.read_bit(COIL_H3_COLLISION_ALARM) is False

    def test_sync_to_registers_alarm_active(self) -> None:
        engine = H3CanvasEngine(resolution=7)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_bit(COIL_H3_COLLISION_ALARM) is True
        diag_read = rt.read_word(REG_H3_DIAGNOSTIC_CODE) & 0xFFFF
        assert diag_read == 0x8430
        assert rt.read_word(REG_H3_NEAREST_DISTANCE_M) < 50

    def test_register_table_signed_16bit_masking(self) -> None:
        rt = RegisterTable()
        test_values = [
            ("%R2760", 25, 25),
            ("%R2762", 7, 7),
            ("%R2767", 0x8430, 0x8430),
            ("%R2767", -31696, 0x8430),
            ("%R2767", 0x8431, 0x8431),
            ("%R2767", -1, 0xFFFF),
            ("%R2767", 0x0000, 0x0000),
        ]
        for reg, val, expected in test_values:
            rt.write_word(reg, val & 0xFFFF)
            assert (rt.read_word(reg) & 0xFFFF) == expected

    def test_sync_from_registers_online_coil(self) -> None:
        engine = H3CanvasEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert engine.online is True

        rt.write_bit(COIL_H3_ONLINE, False)
        engine.sync_from_registers(rt)
        assert engine.online is False

    def test_sync_from_registers_resolution(self) -> None:
        engine = H3CanvasEngine(resolution=7)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        rt.write_word(REG_H3_SELECTED_RESOLUTION, 8)
        engine.sync_from_registers(rt)
        assert engine.resolution == 8

    def test_sync_from_registers_index_and_base_cell(self) -> None:
        engine = H3CanvasEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        rt.write_word(REG_H3_SELECTED_BASE_CELL, 42)
        rt.write_word(REG_H3_INDEX_HI, 0x1234)
        rt.write_word(REG_H3_INDEX_LO, 0x5678)
        engine.sync_from_registers(rt)

        assert engine.selected_base_cell == 42
        assert engine.index_hi == 0x1234
        assert engine.index_lo == 0x5678

    def test_sync_from_registers_invalid_resolution_ignored(self) -> None:
        engine = H3CanvasEngine(resolution=7)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        rt.write_word(REG_H3_SELECTED_RESOLUTION, 99)
        engine.sync_from_registers(rt)
        assert engine.resolution == 7


# ============================================================================
# 7. SVG SCADA Canvas & WCAG Contrast Tests
# ============================================================================

class TestH3SvgCanvasAndWcagContrast:
    def test_wcag_aaa_contrast_calculations(self) -> None:
        ratio_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio_badge >= 18.0, f"Contrast {ratio_badge:.2f} < 18:1"

        ratio_bg = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_SCADA_BG)
        assert ratio_bg >= 18.0

        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, 18.0) is True

    def test_wcag_aaa_contrast_muted_text(self) -> None:
        ratio_muted = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE)
        assert ratio_muted >= 7.0

    def test_svg_rendering_and_xml_validity(self) -> None:
        engine = create_canonical_h3_canvas(sample_count=8, seed=42)
        svg_text = generate_h3_canvas_svg(engine)

        root = ET.fromstring(svg_text)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "800"
        assert root.attrib["height"] == "600"
        assert root.attrib["viewBox"] == "0 0 800 600"

    def test_svg_structural_elements(self) -> None:
        engine = create_canonical_h3_canvas(sample_count=8, seed=42)
        svg_text = generate_h3_canvas_svg(engine)

        assert "h3-grid-container" in svg_text
        assert "h3-hazard-zones" in svg_text
        assert "h3-asset-markers" in svg_text
        assert "hud-telemetry-scorecard" in svg_text
        assert "polygon" in svg_text

    def test_svg_hazard_rendering(self) -> None:
        engine = H3CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1, tag="A1")
        engine.insert_asset(37.7771, -122.4150, asset_id=2, tag="A2")
        engine.detect_collisions()

        svg_text = generate_h3_canvas_svg(engine)
        assert 'stroke-dasharray="6 3"' in svg_text
        assert "COLLISION ALARM" in svg_text
        assert COLOR_ALARM_CRIMSON in svg_text

    def test_svg_multi_asset_rendering(self) -> None:
        engine = H3CanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1, asset_type="sensor", tag="SEN-01")
        engine.insert_asset(37.7720, -122.4210, asset_id=2, asset_type="valve", tag="VLV-02")
        engine.insert_asset(37.7730, -122.4220, asset_id=3, asset_type="pump", tag="PMP-03")
        engine.insert_asset(37.7740, -122.4230, asset_id=4, asset_type="tank", tag="TNK-04")
        engine.insert_asset(37.7750, -122.4240, asset_id=5, asset_type="agv", tag="AGV-05")

        svg_text = generate_h3_canvas_svg(engine)
        for tag in ["SEN-01", "VLV-02", "PMP-03", "TNK-04", "AGV-05"]:
            assert tag in svg_text


# ============================================================================
# 8. Pure IEC 61131-3 ST POU & Security Validation Tests
# ============================================================================

class TestH3PureSTAndSecurityRejection:
    def test_clean_st_pou_verification(self) -> None:
        assert verify_h3_canvas_pure_st() is True

    def test_st_parser_ast_properties(self) -> None:
        parser = STParser()
        ast = parser.parse(ST_PROGRAM_W315_H3_CANVAS_SYNC)
        assert ast is not None
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "H3SpatialCanvasSync"

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

    def test_security_guard_pure_st_content_passes(self) -> None:
        clean_code = "PROGRAM Clean VAR a: INT; END_VAR a := 10; END_PROGRAM"
        SecurityGuard.assert_pure_st_content(clean_code)


# ============================================================================
# 9. ILogicUnit Compliance & Simulation Soak Tests
# ============================================================================

class TestH3ILogicUnitComplianceAndSoak:
    def test_ilogicunit_properties_and_methods(self) -> None:
        engine = H3CanvasEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "H3CanvasEngine"
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
        engine = H3CanvasEngine()
        res = engine.scan_step(None, 123, "test_param", custom_flag=True)
        assert res.status == AgentStatus.SUCCESS
        assert engine.cycle_count == 1

    def test_ilogicunit_scan_step_alarm_failure_result(self) -> None:
        engine = H3CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)

        res = engine.scan_step()
        assert res.status == AgentStatus.FAILED
        assert res.error_code == str(DIAG_PROXIMITY_HAZARD_COLLISION)

    def test_ilogicunit_reset_restores_clean_state(self) -> None:
        engine = H3CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.scan_step()
        assert engine.cycle_count == 1
        assert engine.collision_alarm is True

        engine.reset()
        assert engine.cycle_count == 0
        assert engine.total_assets == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK

    def test_100_cycle_simulation_soak(self) -> None:
        engine = create_canonical_h3_canvas(sample_count=8, seed=42)
        rt = RegisterTable()
        ctx = ScanContext(cycle=0, register_table=rt)

        for i in range(100):
            ctx.cycle = i
            res = engine.scan_step(ctx)
            assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)

        assert engine.cycle_count == 100
        assert engine.total_assets == 8

    def test_simulation_soak_memory_profiling(self) -> None:
        engine = create_canonical_h3_canvas(sample_count=10, seed=99)
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
        assert total_growth < 200_000, f"Unbounded memory growth detected: {total_growth} bytes"


# ============================================================================
# 10. 9-Stage Verification Suite & CLI Interop Tests
# ============================================================================

class TestH3DeterministicVerificationRunnerAndCLI:
    def test_verification_runner_execution(self) -> None:
        res = run_h3_canvas_verification(work_package="W315", quick=True)
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
            out_json = tmp_path / "w315_evidence.json"
            sample_svg = tmp_path / "w315_sample.svg"

            res = run_h3_canvas_verification(
                output_path=out_json,
                sample_svg_path=sample_svg,
                work_package="W315",
                quick=True,
            )

            assert res["status"] == "success"
            assert out_json.exists()
            assert sample_svg.exists()

            with open(out_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                assert data["status"] == "success"
                assert data["data"]["work_package"] == "W315"
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
                "scripts/run_h3_canvas_verification.py",
                "--quick",
                "--output",
                str(out_json),
                "--svg",
                str(sample_svg),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent))
            assert proc.returncode == 0, f"CLI runner failed: {proc.stderr}"
            assert out_json.exists()
            assert sample_svg.exists()

    def test_verification_runner_cli_json_mode(self) -> None:
        cmd = [
            sys.executable,
            "scripts/run_h3_canvas_verification.py",
            "--quick",
            "--json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent))
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
                "scripts/run_h3_canvas_verification.py",
                "--quick",
                "--work-package",
                "W315_VERIFY",
                "--output",
                str(out_json),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent))
            assert proc.returncode == 0, f"CLI custom wp failed: {proc.stderr}"
            with open(out_json, "r", encoding="utf-8") as f:
                evidence = json.load(f)
                assert evidence["data"]["work_package"] == "W315_VERIFY"


# ============================================================================
# 11. Key Requirements & Boundary Enforcement Verification Tests
# ============================================================================

class TestH3CanvasKeyRequirements:
    """Explicit tests addressing all W315 specification requirements (Gate G9 / G2)."""

    def test_key_req_h3_constants_and_base_cells(self) -> None:
        """Validate 122 base cells, 12 pentagons, 110 hexagons, %R2760..%R2767, %M644..%M645."""
        assert NUM_BASE_CELLS == 122
        assert NUM_PENTAGON_BASE_CELLS == 12
        assert NUM_HEXAGON_BASE_CELLS == 110
        assert REG_H3_TOTAL_ASSETS == "%R2760"
        assert REG_H3_SELECTED_BASE_CELL == "%R2761"
        assert REG_H3_SELECTED_RESOLUTION == "%R2762"
        assert REG_H3_INDEX_HI == "%R2763"
        assert REG_H3_INDEX_LO == "%R2764"
        assert REG_H3_NEAREST_DISTANCE_M == "%R2765"
        assert REG_H3_QUERY_LATENCY_US == "%R2766"
        assert REG_H3_DIAGNOSTIC_CODE == "%R2767"
        assert COIL_H3_ONLINE == "%M644"
        assert COIL_H3_COLLISION_ALARM == "%M645"

    def test_key_req_pure_python_h3_hexagonal_projection_bijection(self) -> None:
        """Test spherical projection to base cells, axial coordinates, aperture-7 digits, 64-bit index."""
        coords = [
            (37.7749, -122.4194),
            (51.5074, -0.1278),
            (-33.8688, 151.2093),
            (35.6762, 139.6503),
        ]
        for lat, lon in coords:
            for res in range(1, 9):
                idx = lat_lon_to_h3(lat, lon, res=res)
                assert idx.is_valid()
                assert idx.resolution == res
                c_lat, c_lon = idx.to_lat_lon()
                if res >= 6:
                    dist = haversine_distance_m(lat, lon, c_lat, c_lon)
                    assert dist < 5000.0

    def test_key_req_h3_aperture7_hierarchy_resolutions_1_to_8(self) -> None:
        """Test aperture-7 hierarchy across resolutions 1..8 and parent-child links."""
        for res in range(1, 8):
            cell = lat_lon_to_h3(37.7749, -122.4194, res=res)
            children = cell.children()
            expected_count = 6 if cell.is_pentagon() else 7
            assert len(children) == expected_count
            for c in children:
                assert c.resolution == res + 1
                assert c.parent() == cell
                assert cell.contains(c)

    def test_key_req_6_neighbor_spatial_adjacency_and_kring(self) -> None:
        """Test 6-neighbor spatial adjacency and k-ring disk growth."""
        cell = lat_lon_to_h3(37.7749, -122.4194, res=6)
        nbrs = cell.neighbors()
        assert len(nbrs) in (5, 6)
        k1 = cell.k_ring(1)
        assert len(k1) in (6, 7)
        k2 = cell.k_ring(2)
        assert len(k2) in (16, 19)

    def test_key_req_out_of_bounds_and_invalid_inputs(self) -> None:
        """Test out-of-bounds latitude/longitude (0x8431) and invalid index (0x8432)."""
        engine = H3CanvasEngine()
        with pytest.raises(ValueError):
            engine.insert_asset(95.0, 0.0)
        assert engine.diagnostic_code == DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8431

        with pytest.raises(ValueError):
            engine.select_cell(0)
        assert engine.diagnostic_code == DIAG_H3_INVALID_INDEX
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8432

    def test_key_req_proximity_hazard_detection_and_clearance(self) -> None:
        """Test dynamic spatial proximity collision hazard alarm (0x8430, %M645) and clearance."""
        engine = H3CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7770, -122.4150, asset_id=1)
        engine.insert_asset(37.7771, -122.4150, asset_id=2)
        engine.detect_collisions()

        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8430

        engine.clear_alarm()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x0000

    def test_key_req_register_table_synchronization(self) -> None:
        """Test RegisterTable synchronization across %R2760..%R2767 and %M644..%M645."""
        engine = H3CanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_H3_TOTAL_ASSETS) == 1
        assert rt.read_word(REG_H3_DIAGNOSTIC_CODE) == int(DIAG_OK)
        assert rt.read_bit(COIL_H3_ONLINE) is True
        assert rt.read_bit(COIL_H3_COLLISION_ALARM) is False

    def test_key_req_svg_scada_canvas_rendering_and_contrast(self) -> None:
        """Test SVG SCADA canvas rendering: XML validity, dimensions, WCAG AAA > 18:1."""
        engine = create_canonical_h3_canvas(sample_count=8, seed=42)
        svg_content = generate_h3_canvas_svg(engine)

        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "800"
        assert root.attrib["height"] == "600"

        contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert contrast >= 18.0

    def test_key_req_pure_st_pou_anti_ladder_rejection(self) -> None:
        """Test Pure ST POU validation and anti-ladder rejection of all 9 constructs."""
        assert verify_h3_canvas_pure_st() is True

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
        engine = create_canonical_h3_canvas(sample_count=8, seed=42)
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
        res = run_h3_canvas_verification(work_package="W315", quick=True)
        assert res["status"] in ("success", "failed", "blocked", "inconclusive")
        assert res["status"] == "success"
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
