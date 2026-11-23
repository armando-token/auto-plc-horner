"""Comprehensive Unit Test Suite for Cscape HMI Dynamic Spatial S2 Geometry SCADA Canvas (W312).

Work Package: W312 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial S2 Geometry SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Covers:
1. S2 constants, cube faces (0..5), registers %R2730..%R2737, coils %M637..%M638, diagnostic codes (signed 16-bit safe comparisons)
2. Pure Python S2 spherical projection to cube faces, (u, v) transformations, cell ID generation
3. S2 quadtree hierarchy across levels 1..12 and neighbor adjacency computation
4. Out-of-bounds latitude/longitude inputs handling (0x8425) and invalid cell ID handling (0x8426)
5. Dynamic spatial proximity collision hazard alarm (0x8424, %M638 asserted) and clearance
6. RegisterTable synchronization across %R2730..%R2737 and %M637..%M638
7. SVG SCADA canvas rendering: XML validity, dimensions, asset count, contrast ratio (WCAG AAA > 18:1)
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

from jev_cscape.hmi.s2_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COIL_S2_COLLISION_ALARM,
    COIL_S2_ONLINE,
    COIL_W312_COLLISION_ALARM,
    COIL_W312_ONLINE,
    COIL_W312_S2_ONLINE,
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
    DEFAULT_S2_LEVEL,
    DEFAULT_SAFETY_THRESHOLD_M,
    DEFAULT_VIEWPORT_HEIGHT,
    DEFAULT_VIEWPORT_WIDTH,
    DIAG_COORDINATE_OUT_OF_BOUNDS,
    DIAG_ERR_INVALID_CELL,
    DIAG_ERR_OUT_OF_BOUNDS,
    DIAG_ERR_PROXIMITY_HAZARD,
    DIAG_INVALID_CELL_ID,
    DIAG_OK,
    DIAG_PROXIMITY_HAZARD_COLLISION,
    DIAG_S2_INVALID_CELL_ID,
    DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS,
    DiagnosticCode,
    EARTH_RADIUS_METERS,
    FACE_BASES,
    FACE_COLORS,
    FACE_NAMES,
    MAX_PRECISION,
    MAX_S2_LEVEL,
    MAX_SCADA_LEVEL,
    MIN_PRECISION,
    MIN_S2_LEVEL,
    MIN_SCADA_LEVEL,
    NUM_FACES,
    REG_S2_DIAGNOSTIC_CODE,
    REG_S2_HILBERT_TOKEN_HI,
    REG_S2_HILBERT_TOKEN_LO,
    REG_S2_NEAREST_DISTANCE_M,
    REG_S2_QUERY_LATENCY_US,
    REG_S2_SELECTED_CELL_FACE,
    REG_S2_SELECTED_CELL_LEVEL,
    REG_S2_TOTAL_ASSETS,
    REG_S2_TOTAL_OBJECTS,
    REG_W312_DIAGNOSTIC_CODE,
    REG_W312_HILBERT_TOKEN_HI,
    REG_W312_HILBERT_TOKEN_LO,
    REG_W312_NEAREST_DISTANCE_M,
    REG_W312_QUERY_LATENCY_US,
    REG_W312_SELECTED_CELL_FACE,
    REG_W312_SELECTED_CELL_LEVEL,
    REG_W312_TOTAL_ASSETS,
    REG_W312_TOTAL_OBJECTS,
    S2_CANVAS_PURE_ST_POU,
    S2Asset,
    S2CanvasEngine,
    S2Cell,
    S2CellId,
    S2DiagnosticCode,
    S2Metrics,
    S2Point,
    S2SpatialObject,
    S2StatusBits,
    ST_PROGRAM_S2_CANVAS_SYNC,
    ST_PROGRAM_W312_S2_CANVAS_SYNC,
    SpatialAsset,
    SpatialObject,
    calculate_contrast_ratio,
    cell_id_to_lat_lon,
    cell_id_to_token,
    create_canonical_s2_canvas,
    d2xy,
    face_uv_to_xyz,
    generate_s2_canvas_svg,
    haversine_distance_m,
    ij_to_st,
    lat_lon_to_cell_id,
    lat_lon_to_xyz,
    pack_hilbert_token,
    run_s2_canvas_verification,
    s2_children,
    s2_neighbor,
    s2_neighbors,
    s2_parent,
    s_to_u,
    st_to_ij,
    st_to_uv,
    token_to_cell_id,
    u_to_s,
    unpack_hilbert_token,
    uv_to_st,
    validate_wcag_aaa_contrast,
    verify_s2_canvas_pure_st,
    xy2d,
    xyz_to_face_uv,
    xyz_to_lat_lon,
)


# ============================================================================
# 1. Constants, Cube Faces, Registers & Diagnostic Codes Tests
# ============================================================================

class TestS2ConstantsAndDiagnostics:
    def test_viewport_and_level_constants(self) -> None:
        assert CANVAS_VIEWPORT_WIDTH == 800.0
        assert CANVAS_VIEWPORT_HEIGHT == 600.0
        assert DEFAULT_VIEWPORT_WIDTH == 800.0
        assert DEFAULT_VIEWPORT_HEIGHT == 600.0
        assert MIN_S2_LEVEL == 0
        assert MAX_S2_LEVEL == 30
        assert DEFAULT_S2_LEVEL == 6
        assert MIN_SCADA_LEVEL == 1
        assert MAX_SCADA_LEVEL == 12
        assert MIN_PRECISION == 1
        assert MAX_PRECISION == 12
        assert DEFAULT_PRECISION == 6
        assert DEFAULT_SAFETY_THRESHOLD_M == 50.0
        assert DEFAULT_HAZARD_THRESHOLD == 50.0
        assert EARTH_RADIUS_METERS == 6371000.0

    def test_cube_faces_and_bases_orthonormality(self) -> None:
        assert NUM_FACES == 6
        assert len(FACE_NAMES) == 6
        assert FACE_NAMES == ["+X", "+Y", "+Z", "-X", "-Y", "-Z"]
        assert len(FACE_BASES) == 6
        assert len(FACE_COLORS) == 6

        # Check right-handed orthonormal basis for all 6 faces:
        # W = outward normal, U = horizontal, V = vertical
        # U x V = W, U . V = 0, |U|=|V|=|W|=1
        for face_idx, (W, U, V) in enumerate(FACE_BASES):
            # Dot products U . V == 0
            u_dot_v = U[0] * V[0] + U[1] * V[1] + U[2] * V[2]
            assert abs(u_dot_v) < 1e-9, f"Face {face_idx} basis not orthogonal: U . V = {u_dot_v}"

            # Cross product U x V == W
            cross_x = U[1] * V[2] - U[2] * V[1]
            cross_y = U[2] * V[0] - U[0] * V[2]
            cross_z = U[0] * V[1] - U[1] * V[0]
            assert abs(cross_x - W[0]) < 1e-9
            assert abs(cross_y - W[1]) < 1e-9
            assert abs(cross_z - W[2]) < 1e-9

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
        assert REG_S2_TOTAL_ASSETS == "%R2730"
        assert REG_S2_SELECTED_CELL_FACE == "%R2731"
        assert REG_S2_SELECTED_CELL_LEVEL == "%R2732"
        assert REG_S2_HILBERT_TOKEN_HI == "%R2733"
        assert REG_S2_HILBERT_TOKEN_LO == "%R2734"
        assert REG_S2_NEAREST_DISTANCE_M == "%R2735"
        assert REG_S2_QUERY_LATENCY_US == "%R2736"
        assert REG_S2_DIAGNOSTIC_CODE == "%R2737"
        assert COIL_S2_ONLINE == "%M637"
        assert COIL_S2_COLLISION_ALARM == "%M638"

        # W312 aliases
        assert REG_W312_TOTAL_ASSETS == "%R2730"
        assert REG_W312_TOTAL_OBJECTS == "%R2730"
        assert REG_S2_TOTAL_OBJECTS == "%R2730"
        assert REG_W312_SELECTED_CELL_FACE == "%R2731"
        assert REG_W312_SELECTED_CELL_LEVEL == "%R2732"
        assert REG_W312_HILBERT_TOKEN_HI == "%R2733"
        assert REG_W312_HILBERT_TOKEN_LO == "%R2734"
        assert REG_W312_NEAREST_DISTANCE_M == "%R2735"
        assert REG_W312_QUERY_LATENCY_US == "%R2736"
        assert REG_W312_DIAGNOSTIC_CODE == "%R2737"
        assert COIL_W312_S2_ONLINE == "%M637"
        assert COIL_W312_ONLINE == "%M637"
        assert COIL_W312_COLLISION_ALARM == "%M638"

    def test_diagnostic_codes_values_and_representations(self) -> None:
        assert int(DIAG_OK) == 0x0000
        assert int(DIAG_PROXIMITY_HAZARD_COLLISION) == 0x8424
        assert int(DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS) == 0x8425
        assert int(DIAG_S2_INVALID_CELL_ID) == 0x8426

        assert repr(DIAG_PROXIMITY_HAZARD_COLLISION) == "DiagnosticCode(0x8424)"
        assert str(DIAG_PROXIMITY_HAZARD_COLLISION) == "0x8424"
        assert str(DIAG_OK) == "0x0000"

    def test_diagnostic_codes_signed_16bit_equality(self) -> None:
        # DiagnosticCode implements signed 16-bit safe comparisons
        # 0x8424 is 33828 unsigned, -31708 signed
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8424
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8424 - 0x10000
        assert DIAG_PROXIMITY_HAZARD_COLLISION == -31708

        # 0x8425 is 33829 unsigned, -31707 signed
        assert DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS == 0x8425
        assert DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS == 0x8425 - 0x10000
        assert DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS == -31707

        # 0x8426 is 33830 unsigned, -31706 signed
        assert DIAG_S2_INVALID_CELL_ID == 0x8426
        assert DIAG_S2_INVALID_CELL_ID == 0x8426 - 0x10000
        assert DIAG_S2_INVALID_CELL_ID == -31706

        assert DIAG_OK == 0
        assert DIAG_OK == 0x0000

        # Set containment with DiagnosticCode instances and integers
        code_set = {DIAG_PROXIMITY_HAZARD_COLLISION, DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS}
        assert DIAG_PROXIMITY_HAZARD_COLLISION in code_set
        assert 0x8424 in code_set

    def test_diagnostic_codes_aliases(self) -> None:
        assert DIAG_ERR_PROXIMITY_HAZARD == DIAG_PROXIMITY_HAZARD_COLLISION
        assert DIAG_COORDINATE_OUT_OF_BOUNDS == DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS
        assert DIAG_ERR_OUT_OF_BOUNDS == DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS
        assert DIAG_INVALID_CELL_ID == DIAG_S2_INVALID_CELL_ID
        assert DIAG_ERR_INVALID_CELL == DIAG_S2_INVALID_CELL_ID

        # DiagnosticCode handles alias comparisons
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x8420
        assert DIAG_PROXIMITY_HAZARD_COLLISION == 0x841C
        assert DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS == 0x841D
        assert DIAG_S2_INVALID_CELL_ID == 0x841E

    def test_status_bits(self) -> None:
        assert S2StatusBits.ONLINE == 1
        assert S2StatusBits.COLLISION_ALARM == 2
        assert S2StatusBits.GRID_GENERATED == 4
        assert S2StatusBits.HIGH_DENSITY == 8
        assert S2StatusBits.CELL_SELECTED == 16

        combined = S2StatusBits.ONLINE | S2StatusBits.GRID_GENERATED | S2StatusBits.CELL_SELECTED
        assert (combined & S2StatusBits.ONLINE) != 0
        assert (combined & S2StatusBits.COLLISION_ALARM) == 0
        assert (combined & S2StatusBits.CELL_SELECTED) != 0

    def test_hilbert_token_pack_unpack_roundtrip(self) -> None:
        tokens = [0x00000000, 0x12345678, 0xFFFFFFFF, 0x0000FFFF, 0xABCD0000, 0x5555AAAA]
        for tok in tokens:
            hi, lo = pack_hilbert_token(tok)
            assert 0 <= hi <= 0xFFFF
            assert 0 <= lo <= 0xFFFF
            unpacked = unpack_hilbert_token(hi, lo)
            assert unpacked == tok


# ============================================================================
# 2. Pure Python S2 Spherical Projection & Cell ID Generation Tests
# ============================================================================

class TestS2SphericalProjectionAndCellId:
    def test_s2_point_creation_and_vector_ops(self) -> None:
        p1 = S2Point.from_lat_lon(0.0, 0.0)
        assert abs(p1.x - 1.0) < 1e-9
        assert abs(p1.y) < 1e-9
        assert abs(p1.z) < 1e-9
        assert abs(p1.norm() - 1.0) < 1e-9

        p_north = S2Point.from_lat_lon(90.0, 0.0)
        assert abs(p_north.z - 1.0) < 1e-9

        # Dot and cross products
        assert abs(p1.dot(p_north)) < 1e-9
        cross_p = p1.cross(p_north)
        assert abs(cross_p.y - (-1.0)) < 1e-9

        # Distance
        dist = p1.distance_m(p_north)
        expected_quarter_meridian = EARTH_RADIUS_METERS * (math.pi / 2.0)
        assert abs(dist - expected_quarter_meridian) < 1.0

    def test_lat_lon_xyz_bijection_roundtrip(self) -> None:
        coords = [
            (37.7749, -122.4194),  # San Francisco
            (51.5074, -0.1278),    # London
            (35.6762, 139.6503),   # Tokyo
            (-33.8688, 151.2093),  # Sydney
            (0.0, 0.0),            # Equator & Prime Meridian
            (89.99, 45.0),         # Near North Pole
            (-89.99, -45.0),       # Near South Pole
        ]
        for lat, lon in coords:
            x, y, z = lat_lon_to_xyz(lat, lon)
            r_lat, r_lon = xyz_to_lat_lon(x, y, z)
            assert abs(lat - r_lat) < 1e-6
            assert abs(lon - r_lon) < 1e-6

    def test_face_uv_bijection_roundtrip_all_six_faces(self) -> None:
        for face in range(6):
            for u in [-0.9, -0.5, 0.0, 0.5, 0.9]:
                for v in [-0.9, -0.5, 0.0, 0.5, 0.9]:
                    x, y, z = face_uv_to_xyz(face, u, v)
                    f_res, u_res, v_res = xyz_to_face_uv(x, y, z)
                    assert f_res == face, f"Face mismatch: expected {face}, got {f_res}"
                    assert abs(u - u_res) < 1e-7, f"u mismatch on Face {face}: {u} vs {u_res}"
                    assert abs(v - v_res) < 1e-7, f"v mismatch on Face {face}: {v} vs {v_res}"

    def test_projection_modes_u_to_s_and_s_to_u(self) -> None:
        modes = ["quadratic", "tangent", "linear"]
        u_vals = [-1.0, -0.75, -0.5, 0.0, 0.5, 0.75, 1.0]
        for mode in modes:
            for u in u_vals:
                s = u_to_s(u, mode=mode)
                assert 0.0 <= s <= 1.0
                u_recovered = s_to_u(s, mode=mode)
                assert abs(u - u_recovered) < 1e-7, f"Mode {mode} roundtrip failed for u={u}"

    def test_st_to_ij_and_ij_to_st_quantization(self) -> None:
        for lvl in [1, 3, 6, 10, 12]:
            n = 1 << lvl
            for i in [0, n // 2, n - 1]:
                for j in [0, n // 2, n - 1]:
                    s, t = ij_to_st(i, j, lvl)
                    i_rec, j_rec = st_to_ij(s, t, lvl)
                    assert (i, j) == (i_rec, j_rec)

    def test_hilbert_xy2d_d2xy_bijection(self) -> None:
        for order in range(1, 7):
            n = 1 << order
            test_points = [(0, 0), (0, n - 1), (n - 1, 0), (n - 1, n - 1), (n // 2, n // 2)]
            for x, y in test_points:
                d = xy2d(order, x, y)
                x_rec, y_rec = d2xy(order, d)
                assert (x, y) == (x_rec, y_rec)

    def test_s2_cell_id_64bit_structure_and_sentinel(self) -> None:
        for face in range(6):
            for lvl in range(13):
                cid = S2CellId.from_face_pos_level(face, 0, lvl)
                assert cid.is_valid()
                assert cid.face == face
                assert cid.level == lvl

                # Sentinel bit check
                expected_sentinel_bit = 2 * (30 - lvl)
                assert (cid.id & (1 << expected_sentinel_bit)) != 0
                assert (cid.id & ((1 << expected_sentinel_bit) - 1)) == 0

    def test_s2_cell_id_token_conversion_roundtrip(self) -> None:
        coords = [
            (37.7749, -122.4194),  # San Francisco
            (51.5074, -0.1278),    # London
            (35.6762, 139.6503),   # Tokyo
        ]
        for lat, lon in coords:
            for lvl in [1, 6, 10, 12]:
                cid = S2CellId.from_lat_lon(lat, lon, level=lvl)
                token = cid.to_token()
                assert isinstance(token, str)
                assert len(token) > 0
                cid_parsed = S2CellId.from_token(token)
                assert cid_parsed == cid
                assert cid_parsed.face == cid.face
                assert cid_parsed.level == cid.level


# ============================================================================
# 3. S2 Quadtree Hierarchy Across Levels 1..12 & Adjacency Tests
# ============================================================================

class TestS2QuadtreeHierarchyAndAdjacency:
    def test_quadtree_children_count_and_level(self) -> None:
        for lvl in range(1, 12):
            cell = S2CellId.from_lat_lon(37.7749, -122.4194, level=lvl)
            children = cell.children()
            assert len(children) == 4
            for c in children:
                assert c.level == lvl + 1
                assert c.face == cell.face

    def test_quadtree_parent_child_roundtrip(self) -> None:
        for lvl in range(1, 12):
            cell = S2CellId.from_lat_lon(37.7749, -122.4194, level=lvl)
            children = cell.children()
            for c in children:
                assert c.parent() == cell
                assert cell.contains(c)

    def test_quadtree_spatial_containment_and_intersection(self) -> None:
        parent = S2CellId.from_lat_lon(37.7749, -122.4194, level=6)
        children = parent.children()
        grandchild = children[0].children()[0]

        assert parent.contains(children[0])
        assert parent.contains(grandchild)
        assert parent.intersects(children[0])
        assert parent.intersects(grandchild)

        assert not children[0].contains(parent)
        assert children[0].intersects(children[0])
        assert not children[0].intersects(children[1])

    def test_8_neighbors_dict_keys_and_levels(self) -> None:
        cell = S2CellId.from_lat_lon(37.7749, -122.4194, level=6)
        nbrs = cell.neighbors()
        short_dirs = ["n", "s", "e", "w", "ne", "nw", "se", "sw"]
        long_dirs = ["north", "south", "east", "west", "northeast", "northwest", "southeast", "southwest"]

        for d in short_dirs:
            assert d in nbrs
            assert nbrs[d].level == cell.level
            assert nbrs[d].is_valid()

        for d in long_dirs:
            assert d in nbrs

    def test_cardinal_neighbor_reciprocity_internal_cell(self) -> None:
        # Cell well inside Face 0
        cell = S2CellId.from_face_ij_level(face=0, i=16, j=16, level=6)
        north = cell.neighbor("n")
        south_of_north = north.neighbor("s")
        assert south_of_north == cell

        east = cell.neighbor("e")
        west_of_east = east.neighbor("w")
        assert west_of_east == cell

    def test_neighbor_cross_face_boundary_traversal(self) -> None:
        # Face 0 right boundary stepping east crosses into Face 1 (+Y)
        boundary_cell = S2CellId.from_face_ij_level(face=0, i=31, j=16, level=5)
        east_nbr = boundary_cell.neighbor("east")
        assert east_nbr.is_valid()
        assert east_nbr.face == 1
        assert east_nbr.level == 5

    def test_s2_cell_wrapper_class_methods(self) -> None:
        cell_wrap = S2Cell.from_lat_lon(37.7749, -122.4194, level=6)
        assert cell_wrap.level == 6
        assert 0 <= cell_wrap.face <= 5
        c_lat, c_lon = cell_wrap.center
        assert abs(c_lat - 37.7749) < 1.0
        assert abs(c_lon - (-122.4194)) < 1.0

        verts = cell_wrap.vertices
        assert len(verts) == 4
        assert len(cell_wrap.children()) == 4
        assert cell_wrap.parent().level == 5
        assert len(cell_wrap.neighbors()) >= 8

    def test_global_helper_functions(self) -> None:
        cid_val = lat_lon_to_cell_id(37.7749, -122.4194, level=6)
        assert isinstance(cid_val, int)
        lat, lon = cell_id_to_lat_lon(cid_val)
        assert abs(lat - 37.7749) < 1.0
        assert abs(lon - (-122.4194)) < 1.0

        token_str = cell_id_to_token(cid_val)
        assert token_to_cell_id(token_str) == cid_val

        assert len(s2_children(cid_val)) == 4
        assert s2_parent(cid_val) == S2CellId(cid_val).parent().id
        assert isinstance(s2_neighbor(cid_val, "north"), int)
        assert len(s2_neighbors(cid_val)) >= 8


# ============================================================================
# 4. Out-of-Bounds & Invalid Input Handling Tests
# ============================================================================

class TestS2InputValidationAndErrorHandling:
    def test_out_of_bounds_latitude_high(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            lat_lon_to_xyz(90.1, 0.0)
        with pytest.raises(ValueError, match="out of bounds"):
            S2Point.from_lat_lon(90.1, 0.0)

    def test_out_of_bounds_latitude_low(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            lat_lon_to_xyz(-90.1, 0.0)
        with pytest.raises(ValueError, match="out of bounds"):
            S2Point.from_lat_lon(-90.1, 0.0)

    def test_out_of_bounds_longitude_high(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            lat_lon_to_xyz(0.0, 180.1)
        with pytest.raises(ValueError, match="out of bounds"):
            S2Point.from_lat_lon(0.0, 180.1)

    def test_out_of_bounds_longitude_low(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            lat_lon_to_xyz(0.0, -180.1)
        with pytest.raises(ValueError, match="out of bounds"):
            S2Point.from_lat_lon(0.0, -180.1)

    def test_level_bounds_validation(self) -> None:
        with pytest.raises(ValueError, match="Invalid S2 level"):
            S2CanvasEngine(level=-1)
        with pytest.raises(ValueError, match="Invalid S2 level"):
            S2CanvasEngine(level=31)

    def test_invalid_cell_id_and_token_handling(self) -> None:
        cid_zero = S2CellId(0)
        assert not cid_zero.is_valid()
        with pytest.raises(ValueError, match="Invalid S2 cell ID"):
            cell_id_to_lat_lon(0)

        with pytest.raises(ValueError, match="Invalid S2 cell token"):
            S2CellId.from_token("not_a_valid_hex_token_xyz!")

    def test_invalid_face_uv_bounds(self) -> None:
        with pytest.raises(ValueError, match="Face must be 0..5"):
            face_uv_to_xyz(6, 0.0, 0.0)
        with pytest.raises(ValueError, match="Face must be 0..5"):
            face_uv_to_xyz(-1, 0.0, 0.0)

    def test_unknown_direction_neighbor_rejection(self) -> None:
        cell = S2CellId.from_lat_lon(0.0, 0.0, level=6)
        with pytest.raises(ValueError, match="Unknown direction"):
            cell.neighbor("up")
        with pytest.raises(ValueError, match="Unknown direction"):
            cell.neighbor("down")


# ============================================================================
# 5. Dynamic Spatial Proximity Collision Hazard Alarm Tests
# ============================================================================

class TestS2ProximityHazardCollision:
    def test_haversine_formula_known_distances(self) -> None:
        assert haversine_distance_m(37.77, -122.42, 37.77, -122.42) == 0.0
        d1 = haversine_distance_m(0.0, 0.0, 1.0, 0.0)
        assert 111000.0 < d1 < 112000.0
        d_step = haversine_distance_m(37.7700, -122.4200, 37.7701, -122.4200)
        assert 11.0 < d_step < 11.2

    def test_no_hazards_single_asset(self) -> None:
        engine = S2CanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        hazards = engine.detect_collisions()
        assert len(hazards) == 0
        assert engine.nearest_distance_m == 65535.0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK

    def test_no_hazards_distant_assets(self) -> None:
        engine = S2CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7700, -122.4200, asset_id=1)
        engine.insert_asset(37.7790, -122.4200, asset_id=2)
        hazards = engine.detect_collisions()
        assert len(hazards) == 0
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert engine.nearest_distance_m > 50.0

    def test_collision_hazard_trip_two_close_assets(self) -> None:
        engine = S2CanvasEngine(safety_threshold_m=50.0)
        a1 = engine.insert_asset(37.7750, -122.4180, asset_id=1, tag="VLV-01")
        a2 = engine.insert_asset(37.7751, -122.4180, asset_id=2, tag="AGV-02")
        hazards = engine.detect_collisions()

        assert len(hazards) == 1
        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8424
        assert engine.nearest_distance_m < 50.0
        assert a1.status == "alarm"
        assert a2.status == "alarm"
        assert (engine.status_word & S2StatusBits.COLLISION_ALARM) != 0

    def test_collision_hazard_recovery_on_asset_removal(self) -> None:
        engine = S2CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1)
        engine.insert_asset(37.7751, -122.4180, asset_id=2)
        assert engine.collision_alarm is True

        engine.remove_asset(2)
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (engine.status_word & S2StatusBits.COLLISION_ALARM) == 0

    def test_manual_alarm_clear(self) -> None:
        engine = S2CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1)
        engine.insert_asset(37.7751, -122.4180, asset_id=2)
        assert engine.collision_alarm is True

        engine.clear_alarm()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert len(engine.active_hazards) == 0

    def test_custom_safety_threshold_trip(self) -> None:
        engine = S2CanvasEngine()
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
        engine = S2CanvasEngine(safety_threshold_m=50.0)
        # 3 close assets (~11m apart) and 1 far asset (~1km apart)
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

class TestS2RegisterTableSync:
    def test_sync_to_registers_nominal(self) -> None:
        engine = S2CanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        engine.insert_asset(37.7720, -122.4210, asset_id=2)
        engine.select_cell_by_lat_lon(37.7710, -122.4200)

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_S2_TOTAL_ASSETS) == 2
        assert rt.read_word(REG_S2_SELECTED_CELL_FACE) == engine.selected_face
        assert rt.read_word(REG_S2_SELECTED_CELL_LEVEL) == engine.selected_level
        assert rt.read_word(REG_S2_HILBERT_TOKEN_HI) == engine.hilbert_token_hi
        assert rt.read_word(REG_S2_HILBERT_TOKEN_LO) == engine.hilbert_token_lo
        assert rt.read_word(REG_S2_DIAGNOSTIC_CODE) == int(DIAG_OK)
        assert rt.read_bit(COIL_S2_ONLINE) is True
        assert rt.read_bit(COIL_S2_COLLISION_ALARM) is False

    def test_sync_to_registers_alarm_active(self) -> None:
        engine = S2CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1)
        engine.insert_asset(37.7751, -122.4180, asset_id=2)

        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_bit(COIL_S2_COLLISION_ALARM) is True
        diag_val = rt.read_word(REG_S2_DIAGNOSTIC_CODE) & 0xFFFF
        assert diag_val == (int(DIAG_PROXIMITY_HAZARD_COLLISION) & 0xFFFF)
        dist_val = rt.read_word(REG_S2_NEAREST_DISTANCE_M)
        assert dist_val < 50

    def test_register_table_signed_16bit_masking(self) -> None:
        rt = RegisterTable()
        test_values = [
            ("%R2730", 25, 25),
            ("%R2732", 6, 6),
            ("%R2737", 0x8424, 0x8424),
            ("%R2737", -31708, 0x8424),
            ("%R2737", 0x8425, 0x8425),
            ("%R2737", -1, 0xFFFF),
            ("%R2737", 0x0000, 0x0000),
        ]
        for reg, val, expected in test_values:
            rt.write_word(reg, val & 0xFFFF)
            assert (rt.read_word(reg) & 0xFFFF) == expected

    def test_sync_from_registers_online_coil(self) -> None:
        engine = S2CanvasEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)
        assert engine.online is True

        rt.write_bit(COIL_S2_ONLINE, False)
        engine.sync_from_registers(rt)
        assert engine.online is False

    def test_sync_from_registers_level_and_zoom(self) -> None:
        engine = S2CanvasEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        rt.write_word(REG_S2_SELECTED_CELL_LEVEL, 8)
        engine.sync_from_registers(rt)
        assert engine.level == 8

    def test_sync_from_registers_token_registers(self) -> None:
        engine = S2CanvasEngine()
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        cid = S2CellId.from_lat_lon(37.7749, -122.4194, level=6)
        rt.write_word(REG_S2_SELECTED_CELL_FACE, cid.face)
        rt.write_word(REG_S2_HILBERT_TOKEN_HI, cid.token_hi)
        rt.write_word(REG_S2_HILBERT_TOKEN_LO, cid.token_lo)
        engine.sync_from_registers(rt)

        assert engine.selected_face == cid.face
        assert engine.hilbert_token_hi == cid.token_hi
        assert engine.hilbert_token_lo == cid.token_lo

    def test_sync_from_registers_invalid_level_ignored(self) -> None:
        engine = S2CanvasEngine(level=6)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        rt.write_word(REG_S2_SELECTED_CELL_LEVEL, 99)
        engine.sync_from_registers(rt)
        assert engine.level == 6


# ============================================================================
# 7. SVG SCADA Canvas Rendering & WCAG Contrast Tests
# ============================================================================

class TestS2SvgCanvasAndWcagContrast:
    def test_wcag_aaa_contrast_calculations(self) -> None:
        ratio_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio_badge >= 18.0

        ratio_bg = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_SCADA_BG)
        assert ratio_bg >= 18.0

        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, target_ratio=18.0)

    def test_wcag_aaa_contrast_muted_text(self) -> None:
        ratio_muted = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE)
        assert ratio_muted >= 7.0

    def test_svg_rendering_and_xml_validity(self) -> None:
        engine = create_canonical_s2_canvas(sample_count=8, seed=42)
        svg_text = generate_s2_canvas_svg(engine)

        root = ET.fromstring(svg_text)
        assert root.tag.endswith("svg")
        assert root.attrib.get("width") == "800"
        assert root.attrib.get("height") == "600"
        assert root.attrib.get("viewBox") == "0 0 800 600"

    def test_svg_structural_elements(self) -> None:
        engine = create_canonical_s2_canvas(sample_count=8, seed=42)
        svg_text = generate_s2_canvas_svg(engine)

        assert "s2-grid-container" in svg_text
        assert "s2-hazard-zones" in svg_text
        assert "s2-asset-markers" in svg_text
        assert "hud-telemetry-scorecard" in svg_text

    def test_svg_hazard_rendering(self) -> None:
        engine = S2CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1, tag="A1")
        engine.insert_asset(37.7751, -122.4180, asset_id=2, tag="A2")
        engine.detect_collisions()

        svg_text = generate_s2_canvas_svg(engine)
        assert "hazard-collision-line" in svg_text
        assert "HAZARD" in svg_text

    def test_svg_multi_asset_rendering(self) -> None:
        engine = S2CanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1, asset_type="sensor", tag="SEN-01")
        engine.insert_asset(37.7720, -122.4210, asset_id=2, asset_type="valve", tag="VLV-02")
        engine.insert_asset(37.7730, -122.4220, asset_id=3, asset_type="pump", tag="PMP-03")
        engine.insert_asset(37.7740, -122.4230, asset_id=4, asset_type="tank", tag="TNK-04")
        engine.insert_asset(37.7750, -122.4240, asset_id=5, asset_type="agv", tag="AGV-05")

        svg_text = generate_s2_canvas_svg(engine)
        for tag in ["SEN-01", "VLV-02", "PMP-03", "TNK-04", "AGV-05"]:
            assert tag in svg_text


# ============================================================================
# 8. Pure IEC 61131-3 ST POU & Anti-Ladder Security Rejection Tests
# ============================================================================

class TestS2PureSTAndSecurityRejection:
    def test_clean_st_pou_verification(self) -> None:
        assert verify_s2_canvas_pure_st() is True

    def test_st_parser_pou_ast_properties(self) -> None:
        parser = STParser()
        ast = parser.parse(ST_PROGRAM_W312_S2_CANVAS_SYNC)
        assert ast is not None
        assert ast.pou_type == POUType.PROGRAM
        assert ast.name == "S2SpatialCanvasSync"

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
        SecurityGuard.assert_pure_st_content(clean_code)


# ============================================================================
# 9. ILogicUnit Simulation & 100-Cycle Soak with Memory Profiling Tests
# ============================================================================

class TestS2ILogicUnitComplianceAndSoak:
    def test_ilogicunit_properties_and_methods(self) -> None:
        engine = S2CanvasEngine()
        assert isinstance(engine, ILogicUnit)
        assert engine.name == "S2CanvasEngine"
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
        engine = S2CanvasEngine()
        res = engine.scan_step(None, 123, "test_param", custom_flag=True)
        assert res.status == AgentStatus.SUCCESS
        assert engine.cycle_count == 1

    def test_ilogicunit_scan_step_alarm_failure_result(self) -> None:
        engine = S2CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1)
        engine.insert_asset(37.7751, -122.4180, asset_id=2)

        res = engine.scan_step()
        assert res.status == AgentStatus.FAILED
        assert res.error_code == str(DIAG_PROXIMITY_HAZARD_COLLISION)

    def test_ilogicunit_reset_restores_clean_state(self) -> None:
        engine = S2CanvasEngine(safety_threshold_m=50.0)
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
        engine = create_canonical_s2_canvas(sample_count=8, seed=42)
        rt = RegisterTable()
        ctx = ScanContext(cycle=0, register_table=rt)

        for i in range(100):
            ctx.cycle = i
            res = engine.scan_step(ctx)
            assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)

        assert engine.cycle_count == 100
        assert engine.total_assets == 8

    def test_simulation_soak_memory_profiling(self) -> None:
        engine = create_canonical_s2_canvas(sample_count=10, seed=99)
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

class TestS2DeterministicVerificationRunnerAndCLI:
    def test_verification_runner_execution(self) -> None:
        res = run_s2_canvas_verification(work_package="W312", quick=True)
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
            out_json = tmp_path / "w312_evidence.json"
            sample_svg = tmp_path / "w312_sample.svg"

            res = run_s2_canvas_verification(
                output_path=out_json,
                sample_svg_path=sample_svg,
                work_package="W312",
                quick=True,
            )

            assert res["status"] == "success"
            assert out_json.exists()
            assert sample_svg.exists()

            with open(out_json, "r", encoding="utf-8") as f:
                data = json.load(f)
                assert data["status"] == "success"
                assert data["data"]["work_package"] == "W312"
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
                "scripts/run_s2_canvas_verification.py",
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
            "scripts/run_s2_canvas_verification.py",
            "--quick",
            "--json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
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
                "scripts/run_s2_canvas_verification.py",
                "--quick",
                "--work-package",
                "W312_VERIFY",
                "--output",
                str(out_json),
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            assert proc.returncode == 0
            with open(out_json, "r", encoding="utf-8") as f:
                evidence = json.load(f)
                assert evidence["data"]["work_package"] == "W312_VERIFY"


# ============================================================================
# 11. Key Requirements & Boundary Enforcement Verification Tests
# ============================================================================

class TestS2CanvasKeyRequirements:
    """Explicit tests addressing all W312 specification requirements (Gate G9 / G2)."""

    def test_key_req_s2_constants_and_cube_faces(self) -> None:
        """Validate 6 cube faces, orthonormality, registers %R2730..%R2737, coils %M637..%M638."""
        assert NUM_FACES == 6
        assert len(FACE_BASES) == 6
        assert REG_S2_TOTAL_ASSETS == "%R2730"
        assert REG_S2_SELECTED_CELL_FACE == "%R2731"
        assert REG_S2_SELECTED_CELL_LEVEL == "%R2732"
        assert REG_S2_HILBERT_TOKEN_HI == "%R2733"
        assert REG_S2_HILBERT_TOKEN_LO == "%R2734"
        assert REG_S2_NEAREST_DISTANCE_M == "%R2735"
        assert REG_S2_QUERY_LATENCY_US == "%R2736"
        assert REG_S2_DIAGNOSTIC_CODE == "%R2737"
        assert COIL_S2_ONLINE == "%M637"
        assert COIL_S2_COLLISION_ALARM == "%M638"

    def test_key_req_pure_python_s2_spherical_projection_bijection(self) -> None:
        """Test spherical projection to cube faces, (u, v) transformations, and cell ID generation."""
        coords = [
            (37.7749, -122.4194),
            (51.5074, -0.1278),
            (-33.8688, 151.2093),
            (35.6762, 139.6503),
        ]
        for lat, lon in coords:
            for lvl in range(1, 9):
                cid_val = lat_lon_to_cell_id(lat, lon, level=lvl)
                cid = S2CellId(cid_val)
                assert cid.is_valid()
                assert cid.level == lvl
                c_lat, c_lon = cid.to_lat_lon()
                if lvl >= 6:
                    assert abs(lat - c_lat) < 2.0
                    assert abs(lon - c_lon) < 2.0
                leaf = S2CellId.from_lat_lon(lat, lon, level=12)
                assert cid.contains(leaf) or cid == leaf.parent(lvl)

    def test_key_req_s2_quadtree_hierarchy_levels_1_to_12(self) -> None:
        """Test quadtree hierarchy across levels 1..12 and parent-child links."""
        for lvl in range(1, 12):
            cell = S2CellId.from_lat_lon(37.7749, -122.4194, level=lvl)
            children = cell.children()
            assert len(children) == 4
            for c in children:
                assert c.level == lvl + 1
                assert c.parent() == cell
                assert cell.contains(c)

    def test_key_req_8_neighbor_spatial_adjacency_cross_face(self) -> None:
        """Test 8-neighbor spatial adjacency and cross-face boundary traversal."""
        cell = S2CellId.from_face_ij_level(face=0, i=31, j=16, level=5)
        east_nbr = cell.neighbor("east")
        assert east_nbr.is_valid()
        assert east_nbr.face == 1
        assert east_nbr.level == 5

    def test_key_req_out_of_bounds_and_invalid_inputs(self) -> None:
        """Test out-of-bounds latitude/longitude (0x8425) and invalid cell ID (0x8426)."""
        engine = S2CanvasEngine()
        with pytest.raises(ValueError):
            engine.insert_asset(95.0, 0.0)
        assert engine.diagnostic_code == DIAG_SPHERICAL_COORDINATE_OUT_OF_BOUNDS
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8425

        with pytest.raises(ValueError):
            engine.select_cell(0)
        assert engine.diagnostic_code == DIAG_S2_INVALID_CELL_ID
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8426

    def test_key_req_proximity_hazard_detection_and_clearance(self) -> None:
        """Test dynamic spatial proximity collision hazard alarm (0x8424, %M638) and clearance."""
        engine = S2CanvasEngine(safety_threshold_m=50.0)
        engine.insert_asset(37.7750, -122.4180, asset_id=1)
        engine.insert_asset(37.7751, -122.4180, asset_id=2)

        assert engine.collision_alarm is True
        assert engine.diagnostic_code == DIAG_PROXIMITY_HAZARD_COLLISION
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x8424

        engine.clear_alarm()
        assert engine.collision_alarm is False
        assert engine.diagnostic_code == DIAG_OK
        assert (int(engine.diagnostic_code) & 0xFFFF) == 0x0000

    def test_key_req_register_table_synchronization(self) -> None:
        """Test RegisterTable synchronization across %R2730..%R2737 and %M637..%M638."""
        engine = S2CanvasEngine()
        engine.insert_asset(37.7710, -122.4200, asset_id=1)
        rt = RegisterTable()
        engine.sync_to_registers(rt)

        assert rt.read_word(REG_S2_TOTAL_ASSETS) == 1
        assert rt.read_word(REG_S2_DIAGNOSTIC_CODE) == int(DIAG_OK)
        assert rt.read_bit(COIL_S2_ONLINE) is True
        assert rt.read_bit(COIL_S2_COLLISION_ALARM) is False

    def test_key_req_svg_scada_canvas_rendering_and_contrast(self) -> None:
        """Test SVG SCADA canvas rendering: XML validity, dimensions, WCAG AAA > 18:1."""
        engine = create_canonical_s2_canvas(sample_count=8, seed=42)
        svg_content = generate_s2_canvas_svg(engine)

        root = ET.fromstring(svg_content)
        assert root.tag.endswith("svg")
        assert root.attrib["width"] == "800"
        assert root.attrib["height"] == "600"

        contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert contrast >= 18.0

    def test_key_req_pure_st_pou_anti_ladder_rejection(self) -> None:
        """Test Pure ST POU validation and anti-ladder rejection of all 9 constructs."""
        assert verify_s2_canvas_pure_st() is True

        ladder_tests = [
            "PROGRAM P ---[ ]--- END_PROGRAM",
            "PROGRAM P ---[/]--- END_PROGRAM",
            "PROGRAM P ---( )--- END_PROGRAM",
            "PROGRAM P ---(/)--- END_PROGRAM",
            "PROGRAM P ---(S)--- END_PROGRAM",
            "PROGRAM P ---(R)--- END_PROGRAM",
            "PROGRAM P RUNG 1: X := 1; END_PROGRAM",
            "PROGRAM P XIC Tag1; END_PROGRAM",
            "PROGRAM P OTE Tag1; END_PROGRAM",
        ]
        for ladder in ladder_tests:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(ladder)

    def test_key_req_ilogicunit_simulation_soak_100_cycles_and_memory(self) -> None:
        """Test ILogicUnit simulation soak 100 cycles and memory stability."""
        engine = create_canonical_s2_canvas(sample_count=8, seed=42)
        rt = RegisterTable()
        ctx = ScanContext(cycle=0, register_table=rt)

        for c in range(100):
            ctx.cycle = c
            res = engine.scan_step(ctx)
            assert res.status in (AgentStatus.SUCCESS, AgentStatus.FAILED)

        assert engine.cycle_count == 100
        assert engine.total_assets == 8
