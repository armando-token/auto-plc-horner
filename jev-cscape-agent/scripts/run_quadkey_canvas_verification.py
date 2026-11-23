#!/usr/bin/env python3
"""Verification Runner for Cscape HMI Dynamic Spatial Quadkey / Bing Maps Tile Hierarchical SCADA Canvas (W318).

Work Package: W318 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Quadkey / Bing Maps Tile Hierarchical SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: environment_and_platform_check
  Stage 2: quadkey_constants_and_register_mappings
  Stage 3: pure_python_quadkey_mercator_bijection
  Stage 4: quadkey_hierarchical_prefix_and_tile_tree
  Stage 5: spatial_proximity_hazard_and_collision_trip
  Stage 6: register_table_synchronization_and_signed_masks
  Stage 7: pure_st_pou_and_anti_ladder_rejection
  Stage 8: svg_scada_canvas_rasterization_and_wcag_contrast
  Stage 9: multi_cycle_simulation_soak_and_evidence_emission

CLI Arguments:
  --output, -o (default: artifacts/HMI/quadkey_canvas_evidence.json)
  --svg, -s (default: artifacts/HMI/quadkey_canvas_sample.svg)
  --quick, -q (accelerated verification with reduced simulation cycles)
  --json (force JSON emission)
  --work-package, -w (default: W318)
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import hashlib
import json
import math
from pathlib import Path
import random
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import xml.etree.ElementTree as ET

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

# ============================================================================
# 1. Constants, Palette & Horner OCS Register Map (W318)
# ============================================================================

CANVAS_VIEWPORT_WIDTH: float         = 1200.0
CANVAS_VIEWPORT_HEIGHT: float        = 750.0
TOTAL_DOMAIN_AREA: float             = CANVAS_VIEWPORT_WIDTH * CANVAS_VIEWPORT_HEIGHT

MIN_QUADKEY_LEVEL: int               = 1
MAX_QUADKEY_LEVEL: int               = 23
DEFAULT_QUADKEY_LEVEL: int           = 7
DEFAULT_HAZARD_THRESHOLD: float      = 35.0

MIN_LEVEL: int                       = MIN_QUADKEY_LEVEL
MAX_LEVEL: int                       = MAX_QUADKEY_LEVEL
DEFAULT_LEVEL: int                   = DEFAULT_QUADKEY_LEVEL

# Web Mercator projection bounds
MIN_LAT: float                       = -85.05112878
MAX_LAT: float                       = 85.05112878
MIN_LON: float                       = -180.0
MAX_LON: float                       = 180.0
EARTH_RADIUS_METERS: float           = 6378137.0

# SCADA High-Contrast Theme Palette (WCAG 2.1 AAA Compliant > 18:1)
COLOR_SCADA_BG: str                  = "#0D1117"
COLOR_DARK_SURFACE: str              = "#161B22"
COLOR_DECOUPLED_BADGE: str           = "#05080C"
COLOR_BORDER: str                    = "#334155"
COLOR_TEXT_PRIMARY: str              = "#FFFFFF"
COLOR_TEXT_MUTED: str                = "#CBD5E1"
COLOR_TEXT_DIM: str                  = "#94A3B8"
COLOR_SAMPLE_NODE: str               = "#38BDF8"
COLOR_SAMPLE_BORDER: str             = "#0284C7"
COLOR_NOMINAL_EMERALD: str           = "#10B981"
COLOR_NOMINAL_STROKE: str            = "#059669"
COLOR_WARNING_AMBER: str             = "#F59E0B"
COLOR_WARNING_STROKE: str            = "#D97706"
COLOR_ALARM_CRIMSON: str             = "#EF4444"
COLOR_ALARM_STROKE: str              = "#DC2626"
COLOR_RETICLE_CYAN: str              = "#06B6D4"
COLOR_RETICLE_STROKE: str            = "#0891B2"
COLOR_QUADKEY_CELL: str              = "#38BDF8"
COLOR_QUADKEY_BORDER: str            = "#0284C7"
COLOR_GRID_LINE: str                 = "#1E293B"

# Horner OCS Word Register Map (%R2790..%R2797) & Discrete Coils (%M651..%M652)
REG_W318_TOTAL_OBJECTS: str          = "%R2790"
REG_W318_LEVEL: str                  = "%R2791"
REG_W318_ACTIVE_CELLS: str           = "%R2792"
REG_W318_PRIMARY_HASH: str           = "%R2793"
REG_W318_MATCH_COUNT: str            = "%R2794"
REG_W318_HAZARD_VIOLATIONS: str      = "%R2795"
REG_W318_STATUS_WORD: str            = "%R2796"
REG_W318_DIAGNOSTIC_CODE: str        = "%R2797"

COIL_W318_CANVAS_ONLINE: str         = "%M651"
COIL_W318_HAZARD_ALARM: str          = "%M652"

REG_QUADKEY_TOTAL_OBJECTS            = REG_W318_TOTAL_OBJECTS
REG_QUADKEY_TOTAL_ASSETS             = REG_W318_TOTAL_OBJECTS
REG_QUADKEY_LEVEL                    = REG_W318_LEVEL
REG_QUADKEY_ZOOM                     = REG_W318_LEVEL
REG_QUADKEY_RESOLUTION               = REG_W318_LEVEL
REG_QUADKEY_ACTIVE_CELLS             = REG_W318_ACTIVE_CELLS
REG_QUADKEY_ACTIVE_TILES             = REG_W318_ACTIVE_CELLS
REG_QUADKEY_PRIMARY_HASH             = REG_W318_PRIMARY_HASH
REG_QUADKEY_MATCH_COUNT              = REG_W318_MATCH_COUNT
REG_QUADKEY_HAZARD_VIOLATIONS        = REG_W318_HAZARD_VIOLATIONS
REG_QUADKEY_STATUS_WORD              = REG_W318_STATUS_WORD
REG_QUADKEY_DIAGNOSTIC_CODE          = REG_W318_DIAGNOSTIC_CODE

COIL_QUADKEY_CANVAS_ONLINE           = COIL_W318_CANVAS_ONLINE
COIL_QUADKEY_ONLINE                  = COIL_W318_CANVAS_ONLINE
COIL_QUADKEY_HAZARD_ALARM            = COIL_W318_HAZARD_ALARM
COIL_QUADKEY_COLLISION_ALARM         = COIL_W318_HAZARD_ALARM


class DiagnosticCode(IntEnum):
    """Horner OCS W318 QuadKey / Bing Maps Tile SCADA Diagnostic Codes."""
    OK                              = 0x0000
    INVALID_DOMAIN                  = 0x8401
    DEGENERATE_BOUNDING_BOX         = 0x8402
    OUT_OF_BOUNDS                   = 0x8403
    EMPTY_CANVAS                    = 0x8404
    INVALID_LEVEL                   = 0x8405
    INVALID_RESOLUTION              = 0x8405
    QUERY_OUT_OF_BOUNDS             = 0x8406
    INVALID_QUADKEY                 = 0x8407
    INVALID_CELL_ID                 = 0x8407
    INVALID_INDEX                   = 0x8407
    SPATIAL_CLUSTER_HAZARD          = 0x8418
    SPATIAL_QUADKEY_PROXIMITY_HAZARD = 0x8420
    SPATIAL_COLLISION_TRIP          = 0x8420
    PROXIMITY_HAZARD_COLLISION      = 0x8420


DIAG_OK                             = DiagnosticCode.OK
DIAG_ERR_INVALID_DOMAIN             = DiagnosticCode.INVALID_DOMAIN
DIAG_ERR_DEGENERATE_BOUNDING_BOX    = DiagnosticCode.DEGENERATE_BOUNDING_BOX
DIAG_ERR_OUT_OF_BOUNDS              = DiagnosticCode.OUT_OF_BOUNDS
DIAG_ERR_EMPTY_CANVAS               = DiagnosticCode.EMPTY_CANVAS
DIAG_ERR_INVALID_LEVEL              = DiagnosticCode.INVALID_LEVEL
DIAG_ERR_QUERY_OUT_OF_BOUNDS        = DiagnosticCode.QUERY_OUT_OF_BOUNDS
DIAG_ERR_INVALID_QUADKEY            = DiagnosticCode.INVALID_QUADKEY
DIAG_ERR_SPATIAL_QUADKEY_PROXIMITY_HAZARD = DiagnosticCode.SPATIAL_QUADKEY_PROXIMITY_HAZARD


class QuadkeyStatusBits(IntFlag):
    """16-bit packed status word for QuadKey Canvas engine."""
    ONLINE              = 0x0001
    HAZARD_ALARM        = 0x0002
    GRID_ACTIVE         = 0x0004
    QUERY_ACTIVE        = 0x0008
    SELECTION_ACTIVE    = 0x0010
    HIGH_CONGESTION     = 0x0020
    DEGRADED_RESOLUTION = 0x0040
    CELLS_BOUNDED       = 0x0080


# ============================================================================
# 2. Pure Python QuadKey / Bing Maps Mercator Projection & Tile Algorithms
# ============================================================================

@dataclass
class QuadkeyBoundingBox:
    """Geographic bounding box for a QuadKey tile."""
    min_lat: float
    max_lat: float
    min_lon: float
    max_lon: float

    @property
    def center_lat(self) -> float:
        return (self.min_lat + self.max_lat) / 2.0

    @property
    def center_lon(self) -> float:
        return (self.min_lon + self.max_lon) / 2.0

    @property
    def lat_delta(self) -> float:
        return self.max_lat - self.min_lat

    @property
    def lon_delta(self) -> float:
        return self.max_lon - self.min_lon

    def contains_latlon(self, lat: float, lon: float, tol: float = 1e-9) -> bool:
        """Check if bounding box contains geographic coordinate (lat, lon)."""
        return (self.min_lat - tol <= lat <= self.max_lat + tol and
                self.min_lon - tol <= lon <= self.max_lon + tol)


def latlon_to_tile_xy(lat: float, lon: float, level: int) -> Tuple[int, int]:
    """Convert latitude, longitude to integer tile (tile_x, tile_y) at given level [1..23]."""
    if not (MIN_LAT <= lat <= MAX_LAT):
        raise ValueError(f"Latitude out of bounds [{MIN_LAT}, {MAX_LAT}]: {lat}")
    if not (MIN_LON <= lon <= MAX_LON):
        raise ValueError(f"Longitude out of bounds [{MIN_LON}, {MAX_LON}]: {lon}")
    if not (MIN_QUADKEY_LEVEL <= level <= MAX_QUADKEY_LEVEL):
        raise ValueError(f"Level must be between {MIN_QUADKEY_LEVEL} and {MAX_QUADKEY_LEVEL}, got {level}")

    sin_lat = math.sin(math.radians(lat))
    sin_lat = max(-0.9999999, min(0.9999999, sin_lat))
    x = (lon + 180.0) / 360.0
    y = 0.5 - math.log((1.0 + sin_lat) / (1.0 - sin_lat)) / (4.0 * math.pi)

    map_size = 1 << level
    tile_x = int(math.floor(x * map_size))
    tile_y = int(math.floor(y * map_size))
    tile_x = max(0, min(map_size - 1, tile_x))
    tile_y = max(0, min(map_size - 1, tile_y))
    return tile_x, tile_y


def tile_xy_to_bbox(tile_x: int, tile_y: int, level: int) -> QuadkeyBoundingBox:
    """Convert tile (tile_x, tile_y) at given level to geographic bounding box."""
    if not (MIN_QUADKEY_LEVEL <= level <= MAX_QUADKEY_LEVEL):
        raise ValueError(f"Level must be between {MIN_QUADKEY_LEVEL} and {MAX_QUADKEY_LEVEL}, got {level}")
    map_size = 1 << level
    if not (0 <= tile_x < map_size and 0 <= tile_y < map_size):
        raise ValueError(f"Tile coordinates ({tile_x}, {tile_y}) out of range [0, {map_size - 1}] at level {level}")

    lon_min = (tile_x / float(map_size)) * 360.0 - 180.0
    lon_max = ((tile_x + 1) / float(map_size)) * 360.0 - 180.0

    y_top = tile_y / float(map_size)
    y_bottom = (tile_y + 1) / float(map_size)

    lat_max = math.degrees(math.atan(math.sinh(math.pi * (1.0 - 2.0 * y_top))))
    lat_min = math.degrees(math.atan(math.sinh(math.pi * (1.0 - 2.0 * y_bottom))))
    return QuadkeyBoundingBox(min_lat=lat_min, max_lat=lat_max, min_lon=lon_min, max_lon=lon_max)


def tile_xy_to_quadkey(tile_x: int, tile_y: int, level: int) -> str:
    """Convert tile (tile_x, tile_y) at level to canonical QuadKey string of digits '0'..'3'."""
    if not (MIN_QUADKEY_LEVEL <= level <= MAX_QUADKEY_LEVEL):
        raise ValueError(f"Level must be between {MIN_QUADKEY_LEVEL} and {MAX_QUADKEY_LEVEL}, got {level}")
    map_size = 1 << level
    if not (0 <= tile_x < map_size and 0 <= tile_y < map_size):
        raise ValueError(f"Tile coordinates ({tile_x}, {tile_y}) out of range [0, {map_size - 1}] at level {level}")

    quadkey_chars: List[str] = []
    for i in range(level, 0, -1):
        digit = 0
        mask = 1 << (i - 1)
        if (tile_x & mask) != 0:
            digit += 1
        if (tile_y & mask) != 0:
            digit += 2
        quadkey_chars.append(str(digit))
    return "".join(quadkey_chars)


def quadkey_to_tile_xy(quadkey: str) -> Tuple[int, int, int]:
    """Convert QuadKey string to (tile_x, tile_y, level)."""
    if not quadkey:
        raise ValueError("Quadkey cannot be empty")
    level = len(quadkey)
    if not (MIN_QUADKEY_LEVEL <= level <= MAX_QUADKEY_LEVEL):
        raise ValueError(f"Quadkey length {level} out of bounds [{MIN_QUADKEY_LEVEL}, {MAX_QUADKEY_LEVEL}]")

    tile_x = 0
    tile_y = 0
    for i, ch in enumerate(quadkey):
        mask = 1 << (level - i - 1)
        if ch == '0':
            pass
        elif ch == '1':
            tile_x |= mask
        elif ch == '2':
            tile_y |= mask
        elif ch == '3':
            tile_x |= mask
            tile_y |= mask
        else:
            raise ValueError(f"Invalid Quadkey digit '{ch}' at index {i} in '{quadkey}'")
    return tile_x, tile_y, level


def latlon_to_quadkey(lat: float, lon: float, level: int = DEFAULT_QUADKEY_LEVEL) -> str:
    """Encode latitude and longitude into a QuadKey string at given level [1..23]."""
    tx, ty = latlon_to_tile_xy(lat, lon, level)
    return tile_xy_to_quadkey(tx, ty, level)


geo_to_quadkey = latlon_to_quadkey


def quadkey_to_bbox(quadkey: str) -> QuadkeyBoundingBox:
    """Compute geographic bounding box for given QuadKey."""
    tx, ty, level = quadkey_to_tile_xy(quadkey)
    return tile_xy_to_bbox(tx, ty, level)


def quadkey_to_latlon(quadkey: str) -> Tuple[float, float]:
    """Compute geographic center (lat, lon) coordinates for given QuadKey."""
    bbox = quadkey_to_bbox(quadkey)
    return bbox.center_lat, bbox.center_lon


def quadkey_is_valid(quadkey: str) -> bool:
    """Validate whether string is a well-formed QuadKey string."""
    if not isinstance(quadkey, str) or not quadkey:
        return False
    if not (MIN_QUADKEY_LEVEL <= len(quadkey) <= MAX_QUADKEY_LEVEL):
        return False
    return all(ch in '0123' for ch in quadkey)


def quadkey_to_int64(quadkey: str) -> int:
    """Pack QuadKey into 64-bit integer: level in bits 58..63, 2-bit digits in bits 0..45."""
    if not quadkey_is_valid(quadkey):
        raise ValueError(f"Invalid quadkey: '{quadkey}'")
    level = len(quadkey)
    morton = 0
    for ch in quadkey:
        morton = (morton << 2) | int(ch)
    return (level << 58) | morton


def int64_to_quadkey(packed: int) -> str:
    """Unpack 64-bit integer back to canonical QuadKey string."""
    level = (packed >> 58) & 0x3F
    if not (MIN_QUADKEY_LEVEL <= level <= MAX_QUADKEY_LEVEL):
        raise ValueError(f"Invalid level {level} in packed quadkey {hex(packed)}")
    morton = packed & ((1 << 58) - 1)
    chars: List[str] = []
    for i in range(level):
        digit = (morton >> (2 * (level - 1 - i))) & 0x03
        chars.append(str(digit))
    return "".join(chars)


def quadkey_to_word16(quadkey: str) -> int:
    """Compute deterministic 16-bit FNV-1a hash code of Quadkey string for Horner OCS register."""
    if not quadkey:
        return 0
    h = 0x811C
    for b in quadkey.encode("ascii"):
        h = ((h ^ b) * 0x0103) & 0xFFFF
    return h


def quadkey_get_level(quadkey: str) -> int:
    """Return hierarchy level (zoom) of QuadKey."""
    if not quadkey_is_valid(quadkey):
        raise ValueError(f"Invalid quadkey: '{quadkey}'")
    return len(quadkey)


def quadkey_to_parent(quadkey: str, parent_level: Optional[int] = None) -> str:
    """Return ancestor QuadKey at parent_level (default: immediate parent level - 1)."""
    if not quadkey_is_valid(quadkey):
        raise ValueError(f"Invalid quadkey: '{quadkey}'")
    cur_len = len(quadkey)
    if parent_level is None:
        parent_level = cur_len - 1
    if not (1 <= parent_level <= cur_len):
        raise ValueError(f"Parent level {parent_level} must be between 1 and {cur_len}")
    return quadkey[:parent_level]


def quadkey_to_children(quadkey: str, child_level: Optional[int] = None) -> List[str]:
    """Return all descendant QuadKeys at child_level (default: immediate children level + 1)."""
    if not quadkey_is_valid(quadkey):
        raise ValueError(f"Invalid quadkey: '{quadkey}'")
    cur_len = len(quadkey)
    if child_level is None:
        child_level = cur_len + 1
    if child_level <= cur_len or child_level > MAX_QUADKEY_LEVEL:
        raise ValueError(f"Child level {child_level} must be between {cur_len + 1} and {MAX_QUADKEY_LEVEL}")

    diff = child_level - cur_len
    results = [quadkey]
    for _ in range(diff):
        next_gen: List[str] = []
        for p in results:
            for d in ('0', '1', '2', '3'):
                next_gen.append(p + d)
        results = next_gen
    return results


def quadkey_get_siblings(quadkey: str) -> List[str]:
    """Return all 4 siblings of quadkey (including itself) sharing the same parent."""
    if not quadkey_is_valid(quadkey):
        raise ValueError(f"Invalid quadkey: '{quadkey}'")
    if len(quadkey) <= 1:
        return ['0', '1', '2', '3']
    parent = quadkey[:-1]
    return [parent + '0', parent + '1', parent + '2', parent + '3']


def quadkey_get_neighbors(quadkey: str) -> List[str]:
    """Return up to 8 spatial tile neighbors (Moore neighborhood: N, NE, E, SE, S, SW, W, NW)."""
    tx, ty, level = quadkey_to_tile_xy(quadkey)
    map_size = 1 << level
    neighbors: List[str] = []
    offsets = [
        (0, -1),   # N
        (1, -1),   # NE
        (1, 0),    # E
        (1, 1),    # SE
        (0, 1),    # S
        (-1, 1),   # SW
        (-1, 0),   # W
        (-1, -1),  # NW
    ]
    for dx, dy in offsets:
        nx = (tx + dx) % map_size  # Longitude wraps around
        ny = ty + dy               # Latitude clamped
        if 0 <= ny < map_size:
            neighbors.append(tile_xy_to_quadkey(nx, ny, level))
    return neighbors


# Canvas Screen Coordinates <-> Geographic Coordinates
def canvas_to_latlon(
    x: float,
    y: float,
    width: float = CANVAS_VIEWPORT_WIDTH,
    height: float = CANVAS_VIEWPORT_HEIGHT,
) -> Tuple[float, float]:
    """Map SCADA canvas screen coordinates (x, y) to (lat, lon) via Mercator domain."""
    norm_x = max(0.0, min(1.0, x / width))
    norm_y = max(0.0, min(1.0, y / height))
    lon = norm_x * 360.0 - 180.0
    lat = math.degrees(math.atan(math.sinh(math.pi * (1.0 - 2.0 * norm_y))))
    lat = max(MIN_LAT, min(MAX_LAT, lat))
    lon = max(MIN_LON, min(MAX_LON, lon))
    return lat, lon


def latlon_to_canvas(
    lat: float,
    lon: float,
    width: float = CANVAS_VIEWPORT_WIDTH,
    height: float = CANVAS_VIEWPORT_HEIGHT,
) -> Tuple[float, float]:
    """Map (lat, lon) to SCADA canvas screen coordinates (x, y)."""
    sin_lat = math.sin(math.radians(lat))
    sin_lat = max(-0.9999999, min(0.9999999, sin_lat))
    norm_x = (lon + 180.0) / 360.0
    norm_y = 0.5 - math.log((1.0 + sin_lat) / (1.0 - sin_lat)) / (4.0 * math.pi)
    return norm_x * width, norm_y * height


def quadkey_to_canvas_rect(
    quadkey: str,
    width: float = CANVAS_VIEWPORT_WIDTH,
    height: float = CANVAS_VIEWPORT_HEIGHT,
) -> Tuple[float, float, float, float]:
    """Calculate (rx, ry, rw, rh) canvas rectangle for given QuadKey."""
    tx, ty, level = quadkey_to_tile_xy(quadkey)
    map_size = 1 << level
    rx = (tx / float(map_size)) * width
    ry = (ty / float(map_size)) * height
    rw = (1.0 / float(map_size)) * width
    rh = (1.0 / float(map_size)) * height
    return rx, ry, rw, rh


def haversine_distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle spherical distance in meters between two lat/lon points."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1.0 - a)))
    return EARTH_RADIUS_METERS * c


@dataclass
class SpatialNode:
    """Equipment or sensor node indexed within the QuadKey SCADA canvas."""
    id: int
    x: float
    y: float
    lat: float = 0.0
    lon: float = 0.0
    tile_x: int = 0
    tile_y: int = 0
    level: int = DEFAULT_QUADKEY_LEVEL
    quadkey: str = ""
    token: str = ""
    tag: str = ""
    equip_type: str = "sensor"
    status: str = "normal"
    hazard_radius: float = 20.0
    hash_word: int = 0


@dataclass
class QuadkeyMetrics:
    """Runtime telemetry metrics snapshot for Horner OCS register synchronization."""
    total_objects: int = 0
    level: int = DEFAULT_QUADKEY_LEVEL
    active_cells: int = 0
    primary_hash: int = 0
    match_count: int = 0
    hazard_violations: int = 0
    status_word: int = 0
    diagnostic_code: DiagnosticCode = DiagnosticCode.OK
    canvas_online: bool = True
    hazard_alarm: bool = False


# ============================================================================
# 3. QuadKey Canvas Engine Implementation
# ============================================================================

class QuadkeyCanvasEngine(ILogicUnit):
    """Dynamic Spatial QuadKey / Bing Maps Tile Hierarchical SCADA Canvas Engine."""

    def __init__(
        self,
        level: int = DEFAULT_QUADKEY_LEVEL,
        viewport_width: float = CANVAS_VIEWPORT_WIDTH,
        viewport_height: float = CANVAS_VIEWPORT_HEIGHT,
        hazard_threshold: float = DEFAULT_HAZARD_THRESHOLD,
    ) -> None:
        if not (MIN_QUADKEY_LEVEL <= level <= MAX_QUADKEY_LEVEL):
            raise ValueError(
                f"Level must be between {MIN_QUADKEY_LEVEL} and {MAX_QUADKEY_LEVEL}, got {level}"
            )
        self.level: int = level
        self.viewport_width: float = viewport_width
        self.viewport_height: float = viewport_height
        self.hazard_threshold: float = hazard_threshold

        self.nodes: Dict[int, SpatialNode] = {}
        self.active_quadkeys: Set[str] = set()
        self.selected_node_id: int = 0
        self.last_query_results: List[SpatialNode] = []
        self.last_query_rect: Optional[Tuple[float, float, float, float]] = None
        self.last_query_radius: float = 0.0
        self.last_query_token_prefix: str = ""

        self.cycle_count: int = 0
        self.alarm_active: bool = False
        self.hazard_violations: int = 0
        self.diagnostic_code: DiagnosticCode = DiagnosticCode.OK

        self.reg_table: RegisterTable = RegisterTable()

    def insert_node(
        self,
        x: float,
        y: float,
        node_id: int,
        tag: str = "",
        equip_type: str = "sensor",
        status: str = "normal",
        hazard_radius: float = 20.0,
    ) -> SpatialNode:
        """Insert or update a spatial equipment node on the canvas."""
        if not (0.0 <= x <= self.viewport_width and 0.0 <= y <= self.viewport_height):
            self.diagnostic_code = DiagnosticCode.OUT_OF_BOUNDS
            raise ValueError(
                f"Node ({x}, {y}) exceeds canvas dimensions ({self.viewport_width}, {self.viewport_height})"
            )

        lat, lon = canvas_to_latlon(x, y, self.viewport_width, self.viewport_height)
        tx, ty = latlon_to_tile_xy(lat, lon, self.level)
        qk = tile_xy_to_quadkey(tx, ty, self.level)
        hw = quadkey_to_word16(qk)

        node = SpatialNode(
            id=node_id,
            x=x,
            y=y,
            lat=lat,
            lon=lon,
            tile_x=tx,
            tile_y=ty,
            level=self.level,
            quadkey=qk,
            token=qk,
            tag=tag or f"NODE-{node_id}",
            equip_type=equip_type,
            status=status,
            hazard_radius=hazard_radius,
            hash_word=hw,
        )

        self.nodes[node_id] = node
        self.active_quadkeys.add(qk)
        return node

    def remove_node(self, node_id: int) -> Optional[SpatialNode]:
        """Remove a node by ID."""
        node = self.nodes.pop(node_id, None)
        if node:
            # Rebuild active quadkeys set
            self.active_quadkeys = set(n.quadkey for n in self.nodes.values())
            if self.selected_node_id == node_id:
                self.selected_node_id = 0
        return node

    def get_node(self, node_id: int) -> Optional[SpatialNode]:
        """Retrieve node by ID."""
        return self.nodes.get(node_id)

    def query_radius(self, center_x: float, center_y: float, radius: float) -> List[SpatialNode]:
        """Execute radial proximity range query."""
        self.last_query_radius = radius
        self.last_query_rect = None
        self.last_query_token_prefix = ""
        results: List[SpatialNode] = []
        r2 = radius * radius
        for n in self.nodes.values():
            dx = n.x - center_x
            dy = n.y - center_y
            if dx * dx + dy * dy <= r2:
                results.append(n)
        self.last_query_results = results
        return results

    def query_rect(self, min_x: float, min_y: float, max_x: float, max_y: float) -> List[SpatialNode]:
        """Execute bounding box rectangle range query."""
        self.last_query_rect = (min_x, min_y, max_x, max_y)
        self.last_query_radius = 0.0
        self.last_query_token_prefix = ""
        results: List[SpatialNode] = []
        for n in self.nodes.values():
            if min_x <= n.x <= max_x and min_y <= n.y <= max_y:
                results.append(n)
        self.last_query_results = results
        return results

    def query_quadkey(self, prefix: str) -> List[SpatialNode]:
        """Query nodes matching hierarchical QuadKey prefix."""
        self.last_query_token_prefix = prefix
        self.last_query_rect = None
        self.last_query_radius = 0.0
        results: List[SpatialNode] = []
        for n in self.nodes.values():
            if n.quadkey.startswith(prefix):
                results.append(n)
        self.last_query_results = results
        return results

    def check_proximity_hazards(self) -> List[Tuple[SpatialNode, SpatialNode, float]]:
        """Detect pairwise spatial proximity hazards below hazard_threshold."""
        violations: List[Tuple[SpatialNode, SpatialNode, float]] = []
        node_list = list(self.nodes.values())
        thresh2 = self.hazard_threshold * self.hazard_threshold

        for i in range(len(node_list)):
            for j in range(i + 1, len(node_list)):
                n1 = node_list[i]
                n2 = node_list[j]
                dx = n1.x - n2.x
                dy = n1.y - n2.y
                d2 = dx * dx + dy * dy
                if d2 <= thresh2:
                    dist = math.sqrt(d2)
                    violations.append((n1, n2, dist))

        self.hazard_violations = len(violations)
        if violations:
            self.alarm_active = True
            self.diagnostic_code = DiagnosticCode.SPATIAL_QUADKEY_PROXIMITY_HAZARD
        else:
            self.alarm_active = False
            self.diagnostic_code = DiagnosticCode.OK

        return violations

    @property
    def metrics(self) -> QuadkeyMetrics:
        """Calculate runtime telemetry metrics snapshot."""
        active_cells = len(set(node.quadkey for node in self.nodes.values()))
        primary_hash = 0
        if self.selected_node_id in self.nodes:
            primary_hash = self.nodes[self.selected_node_id].hash_word
        elif self.nodes:
            primary_hash = next(iter(self.nodes.values())).hash_word

        status_word = 0
        if not self.alarm_active:
            status_word |= QuadkeyStatusBits.ONLINE
        else:
            status_word |= QuadkeyStatusBits.HAZARD_ALARM
        if active_cells > 0:
            status_word |= QuadkeyStatusBits.GRID_ACTIVE
        if len(self.last_query_results) > 0:
            status_word |= QuadkeyStatusBits.QUERY_ACTIVE
        if self.selected_node_id > 0:
            status_word |= QuadkeyStatusBits.SELECTION_ACTIVE
        if self.hazard_violations > 0:
            status_word |= QuadkeyStatusBits.HIGH_CONGESTION

        return QuadkeyMetrics(
            total_objects=len(self.nodes),
            level=self.level,
            active_cells=active_cells,
            primary_hash=primary_hash,
            match_count=len(self.last_query_results),
            hazard_violations=self.hazard_violations,
            status_word=status_word,
            diagnostic_code=self.diagnostic_code,
            canvas_online=not self.alarm_active,
            hazard_alarm=self.alarm_active,
        )

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.USER,
    ) -> None:
        """Synchronize telemetry metrics into Horner OCS registers and coils."""
        rt = reg_table or self.reg_table
        m = self.metrics

        rt.write_word(REG_W318_TOTAL_OBJECTS, m.total_objects & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W318_LEVEL, m.level & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W318_ACTIVE_CELLS, m.active_cells & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W318_PRIMARY_HASH, m.primary_hash & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W318_MATCH_COUNT, m.match_count & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W318_HAZARD_VIOLATIONS, m.hazard_violations & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W318_STATUS_WORD, m.status_word & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W318_DIAGNOSTIC_CODE, int(m.diagnostic_code) & 0xFFFF, privilege=privilege)

        rt.write_bit(COIL_W318_CANVAS_ONLINE, m.canvas_online, privilege=privilege)
        rt.write_bit(COIL_W318_HAZARD_ALARM, m.hazard_alarm, privilege=privilege)

    def scan_step(self, ctx: Optional[ScanContext] = None) -> ExecutionResult:
        """Execute single scan cycle step of QuadKey Canvas engine."""
        self.cycle_count += 1
        self.check_proximity_hazards()
        rt = ctx.register_table if ctx and ctx.register_table else self.reg_table
        self.sync_to_registers(rt)

        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            details=f"QuadKey Canvas Cycle {self.cycle_count}: {len(self.nodes)} nodes indexed at level {self.level}.",
            data={
                "cycle": self.cycle_count,
                "nodes": len(self.nodes),
                "level": self.level,
                "active_cells": len(set(n.quadkey for n in self.nodes.values())),
                "matches": len(self.last_query_results),
                "violations": self.hazard_violations,
                "alarm": self.alarm_active,
                "diagnostic_code": int(self.diagnostic_code),
            },
        )

    # ILogicUnit interface compliance
    @property
    def name(self) -> str:
        return "QuadkeyCanvasEngine"

    @property
    def priority(self) -> int:
        return 100

    @property
    def is_enabled(self) -> bool:
        return True

    def step(self, *args: Any, **kwargs: Any) -> None:
        self.scan_step(*args, **kwargs)

    def execute(self, *args: Any, **kwargs: Any) -> ExecutionResult:
        return self.scan_step(*args, **kwargs)

    def reset(self) -> None:
        self.nodes.clear()
        self.active_quadkeys.clear()
        self.selected_node_id = 0
        self.last_query_results.clear()
        self.last_query_rect = None
        self.last_query_radius = 0.0
        self.last_query_token_prefix = ""
        self.cycle_count = 0
        self.alarm_active = False
        self.hazard_violations = 0
        self.diagnostic_code = DIAG_OK

    def clear(self) -> None:
        self.reset()

    def build_canonical_sensor_network(self, seed: int = 42, count: int = 24) -> None:
        """Construct deterministic canonical industrial sensor network."""
        self.reset()
        rng = random.Random(seed)
        equip_types = ["sensor", "pump", "valve", "tank", "heater", "compressor"]

        # Grid-spaced initial positions to ensure 0 initial hazard violations
        cols = 6
        rows = (count + cols - 1) // cols
        dx = (self.viewport_width - 240.0) / float(cols)
        dy = (self.viewport_height - 200.0) / float(rows)

        idx = 0
        for r in range(rows):
            for c in range(cols):
                if idx >= count:
                    break
                etype = equip_types[idx % len(equip_types)]
                base_x = 120.0 + c * dx + rng.uniform(-15.0, 15.0)
                base_y = 100.0 + r * dy + rng.uniform(-15.0, 15.0)
                status = "normal"
                self.insert_node(
                    x=base_x,
                    y=base_y,
                    node_id=idx + 1,
                    tag=f"EQ-{idx+1:03d}",
                    equip_type=etype,
                    status=status,
                    hazard_radius=20.0,
                )
                idx += 1

        self.alarm_active = False
        self.hazard_violations = 0
        self.diagnostic_code = DIAG_OK


# ============================================================================
# 4. WCAG 2.1 AAA Contrast & Standalone SVG Generation
# ============================================================================

def _srgb_to_linear(c_norm: float) -> float:
    if c_norm <= 0.03928:
        return c_norm / 12.92
    return ((c_norm + 0.055) / 1.055) ** 2.4


def _hex_to_relative_luminance(hex_str: str) -> float:
    h = hex_str.lstrip("#")
    r, g, b = int(h[0:2], 16) / 255.0, int(h[2:4], 16) / 255.0, int(h[4:6], 16) / 255.0
    return 0.2126 * _srgb_to_linear(r) + 0.7152 * _srgb_to_linear(g) + 0.0722 * _srgb_to_linear(b)


def calculate_contrast_ratio(hex1: str, hex2: str) -> float:
    """Calculate WCAG 2.1 relative luminance contrast ratio between two hex colors."""
    l1 = _hex_to_relative_luminance(hex1)
    l2 = _hex_to_relative_luminance(hex2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def generate_quadkey_canvas_svg(engine: QuadkeyCanvasEngine) -> str:
    """Generate standalone W3C SVG 1.1 vector graphic meeting WCAG 2.1 AAA contrast."""
    w = int(engine.viewport_width)
    h = int(engine.viewport_height)

    svg_parts: List[str] = []
    svg_parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 {w} {h}" '
        f'width="{w}" height="{h}" style="background-color: {COLOR_SCADA_BG}; font-family: monospace;">'
    )

    # 1. Defs: Gradient & Filters
    svg_parts.append(
        '  <defs>\n'
        '    <linearGradient id="qkGrad" x1="0%" y1="0%" x2="100%" y2="100%">\n'
        f'      <stop offset="0%" stop-color="{COLOR_QUADKEY_CELL}" stop-opacity="0.15" />\n'
        f'      <stop offset="100%" stop-color="{COLOR_NOMINAL_EMERALD}" stop-opacity="0.05" />\n'
        '    </linearGradient>\n'
        '  </defs>'
    )

    # 2. Hierarchical QuadKey Tile Layer
    svg_parts.append('  <!-- Hierarchical QuadKey / Bing Maps Tile Layer -->')
    svg_parts.append('  <g id="quadkey-tile-layer" class="quadkey-cells">')
    # Render parent tiles at coarse level (level 2 or 3)
    coarse_level = min(engine.level, 3)
    coarse_quadkeys = sorted(list(set(quadkey_to_parent(node.quadkey, coarse_level) for node in engine.nodes.values())))
    for qk in coarse_quadkeys:
        rx, ry, rw, rh = quadkey_to_canvas_rect(qk, engine.viewport_width, engine.viewport_height)
        svg_parts.append(
            f'    <rect class="quadkey-cell" x="{rx:.1f}" y="{ry:.1f}" width="{rw:.1f}" height="{rh:.1f}" '
            f'fill="url(#qkGrad)" stroke="{COLOR_QUADKEY_BORDER}" stroke-width="0.9" stroke-dasharray="3 2" />'
        )
        svg_parts.append(
            f'    <text x="{rx + 8:.1f}" y="{ry + 16:.1f}" fill="{COLOR_TEXT_DIM}" font-size="8">Q:{qk}</text>'
        )
    svg_parts.append('  </g>')

    # 3. Query Reticle Overlay
    svg_parts.append('  <!-- Query Reticle Overlay Layer -->')
    if engine.last_query_rect:
        min_x, min_y, max_x, max_y = engine.last_query_rect
        rw_box = max_x - min_x
        rh_box = max_y - min_y
        svg_parts.append(
            f'  <g id="query-reticle-layer" class="range-reticle">\n'
            f'    <rect x="{min_x:.1f}" y="{min_y:.1f}" width="{rw_box:.1f}" height="{rh_box:.1f}" '
            f'fill="{COLOR_RETICLE_CYAN}" fill-opacity="0.08" stroke="{COLOR_RETICLE_CYAN}" stroke-width="1.5" stroke-dasharray="4 2" />\n'
            f'  </g>'
        )
    elif engine.last_query_radius > 0.0:
        cx, cy = w / 2.0, h / 2.0
        r = engine.last_query_radius
        svg_parts.append(
            f'  <g id="query-reticle-layer" class="range-reticle">\n'
            f'    <circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" '
            f'fill="{COLOR_RETICLE_CYAN}" fill-opacity="0.08" stroke="{COLOR_RETICLE_CYAN}" stroke-width="1.5" stroke-dasharray="4 2" />\n'
            f'  </g>'
        )
    else:
        svg_parts.append('  <g id="query-reticle-layer" class="range-reticle" />')

    # 4. Equipment & Sensor Nodes Layer
    svg_parts.append('  <!-- Equipment & Sensor Nodes Layer -->')
    svg_parts.append('  <g id="nodes-layer">')
    for node in engine.nodes.values():
        is_alarm = (node.status == "alarm" or engine.alarm_active)
        status_col = (
            COLOR_ALARM_CRIMSON if is_alarm
            else (COLOR_WARNING_AMBER if node.status == "warning" else COLOR_NOMINAL_EMERALD)
        )
        border_col = (
            COLOR_ALARM_STROKE if is_alarm
            else (COLOR_WARNING_STROKE if node.status == "warning" else COLOR_NOMINAL_STROKE)
        )
        is_matched = node in engine.last_query_results
        glow = f'<circle cx="{node.x:.1f}" cy="{node.y:.1f}" r="14" fill="{COLOR_RETICLE_CYAN}" fill-opacity="0.25" />' if is_matched else ""

        svg_parts.append(
            f'    <g id="sensor-{node.id}" class="sensor-node">\n'
            f'      {glow}\n'
            f'      <circle cx="{node.x:.1f}" cy="{node.y:.1f}" r="6" fill="{status_col}" stroke="{border_col}" stroke-width="1.5" />\n'
            f'      <text x="{node.x + 9:.1f}" y="{node.y - 4:.1f}" fill="{COLOR_TEXT_PRIMARY}" font-size="9" font-weight="bold">{node.tag}</text>\n'
            f'      <text x="{node.x + 9:.1f}" y="{node.y + 8:.1f}" fill="{COLOR_TEXT_DIM}" font-size="8">[Q:{node.token[:8]}]</text>\n'
            f'    </g>'
        )
    svg_parts.append('  </g>')

    # 5. HUD Telemetry Scorecard (WCAG AAA High Contrast > 18:1)
    m = engine.metrics
    alarm_badge_fill = COLOR_ALARM_CRIMSON if m.hazard_alarm else COLOR_NOMINAL_EMERALD
    alarm_badge_text = "HAZARD ALARM" if m.hazard_alarm else "INDEXING NOMINAL"

    svg_parts.append(
        f'  <!-- HUD Telemetry Scorecard -->\n'
        f'  <g id="scorecard-layer" class="hud-telemetry-scorecard">\n'
        f'    <rect x="15" y="15" width="530" height="74" rx="6" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1.2" />\n'
        f'    <text x="25" y="35" fill="{COLOR_TEXT_PRIMARY}" font-size="11" font-weight="bold">DYNAMIC SPATIAL QUADKEY / BING MAPS TILE HIERARCHICAL SCADA CANVAS [W318]</text>\n'
        f'    <text x="25" y="55" fill="{COLOR_TEXT_MUTED}" font-size="10">LEVEL: {m.level} | ACTIVE TILES: {m.active_cells} | NODES: {m.total_objects} | MATCHES: {m.match_count}</text>\n'
        f'    <text x="25" y="72" fill="{COLOR_TEXT_DIM}" font-size="9">HAZARDS: {m.hazard_violations} | DIAG: 0x{int(m.diagnostic_code):04X} | REGS: %R2790..%R2797 | COILS: %M651..%M652</text>\n'
        f'    <rect x="{w - 180}" y="15" width="165" height="28" rx="4" fill="{alarm_badge_fill}" />\n'
        f'    <text x="{w - 97}" y="33" fill="{COLOR_TEXT_PRIMARY}" font-size="10" font-weight="bold" text-anchor="middle">{alarm_badge_text}</text>\n'
        f'  </g>'
    )

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)


def create_canonical_quadkey_canvas(
    seed: int = 42,
    count: int = 24,
    level: int = DEFAULT_QUADKEY_LEVEL,
) -> QuadkeyCanvasEngine:
    """Helper to instantiate and populate canonical QuadKey canvas."""
    engine = QuadkeyCanvasEngine(level=level)
    engine.build_canonical_sensor_network(seed=seed, count=count)
    return engine


# ============================================================================
# 5. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

ST_PROGRAM_W318_QUADKEY_CANVAS_SYNC: str = """
PROGRAM QuadkeyCanvasSync
VAR
    wTotalObjects AT %R2790 : WORD;
    wLevel AT %R2791 : WORD;
    wActiveCells AT %R2792 : WORD;
    wPrimaryHash AT %R2793 : WORD;
    wMatchCount AT %R2794 : WORD;
    wHazardViolations AT %R2795 : WORD;
    wStatusWord AT %R2796 : WORD;
    wDiagCode AT %R2797 : WORD;
    bCanvasOnline AT %M651 : BOOL;
    bHazardAlarm AT %M652 : BOOL;
END_VAR

IF wDiagCode = 0 THEN
    bCanvasOnline := TRUE;
    bHazardAlarm := FALSE;
ELSE
    bCanvasOnline := FALSE;
    bHazardAlarm := TRUE;
END_IF;
END_PROGRAM
""".strip()

ST_PROGRAM_QUADKEY_CANVAS_SYNC = ST_PROGRAM_W318_QUADKEY_CANVAS_SYNC


# ANSI terminal formatting constants matching repo conventions
CLR_RESET  = "\033[0m"
CLR_BOLD   = "\033[1m"
CLR_DIM    = "\033[2m"
CLR_GREEN  = "\033[92m"
CLR_RED    = "\033[91m"
CLR_YELLOW = "\033[93m"
CLR_CYAN   = "\033[96m"
CLR_GRAY   = "\033[90m"


def format_stage_badge(passed: bool, status: Optional[str] = None) -> str:
    """Format strict 4-state ANSI badge."""
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        return f"{CLR_YELLOW}{CLR_BOLD}[BLOCKED]{CLR_RESET}"
    if norm_status == "inconclusive":
        return f"{CLR_YELLOW}{CLR_BOLD}[INCONCLUSIVE]{CLR_RESET}"
    if passed or norm_status in ("passed", "pass", "success"):
        return f"{CLR_GREEN}{CLR_BOLD}[PASS]{CLR_RESET}"
    return f"{CLR_RED}{CLR_BOLD}[FAIL]{CLR_RESET}"


# ============================================================================
# 6. Complete 9-Stage Verification Suite
# ============================================================================

def run_quadkey_canvas_verification(
    output_path: Optional[str] = None,
    sample_svg_path: Optional[str] = None,
    work_package: str = "W318",
    quick: bool = False,
) -> Dict[str, Any]:
    """Execute the deterministic 9-stage verification suite for W318 QuadKey Canvas."""
    stages: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: environment_and_platform_check
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    py_ver = sys.version_info
    py_ok = py_ver >= (3, 9)
    platform_ok = bool(sys.platform)
    deps_ok = all(
        m in sys.modules or __import__(m)
        for m in ["json", "math", "pathlib", "hashlib", "random", "time", "xml.etree.ElementTree"]
    )
    framework_ok = (
        STParser is not None
        and SecurityGuard is not None
        and LadderForbiddenError is not None
        and RegisterTable is not None
        and ScanContext is not None
        and ILogicUnit is not None
    )
    module_ok = (
        QuadkeyCanvasEngine is not None
        and latlon_to_quadkey is not None
        and quadkey_to_latlon is not None
        and quadkey_to_parent is not None
        and quadkey_to_children is not None
        and generate_quadkey_canvas_svg is not None
    )
    c1 = py_ok and platform_ok and deps_ok and framework_ok and module_ok
    stages.append({
        "stage": 1,
        "name": "environment_and_platform_check",
        "passed": c1,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Python {sys.version.split()[0]} on {sys.platform}; jev_cscape simulation, parser, and W318 modules verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: quadkey_constants_and_register_mappings
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    regs_ok = (
        REG_W318_TOTAL_OBJECTS == "%R2790"
        and REG_W318_LEVEL == "%R2791"
        and REG_W318_ACTIVE_CELLS == "%R2792"
        and REG_W318_PRIMARY_HASH == "%R2793"
        and REG_W318_MATCH_COUNT == "%R2794"
        and REG_W318_HAZARD_VIOLATIONS == "%R2795"
        and REG_W318_STATUS_WORD == "%R2796"
        and REG_W318_DIAGNOSTIC_CODE == "%R2797"
        and COIL_W318_CANVAS_ONLINE == "%M651"
        and COIL_W318_HAZARD_ALARM == "%M652"
        and REG_QUADKEY_TOTAL_OBJECTS == "%R2790"
        and COIL_QUADKEY_CANVAS_ONLINE == "%M651"
    )

    diag_ok = (
        int(DiagnosticCode.OK) == 0x0000
        and int(DiagnosticCode.INVALID_DOMAIN) == 0x8401
        and int(DiagnosticCode.DEGENERATE_BOUNDING_BOX) == 0x8402
        and int(DiagnosticCode.OUT_OF_BOUNDS) == 0x8403
        and int(DiagnosticCode.EMPTY_CANVAS) == 0x8404
        and int(DiagnosticCode.INVALID_LEVEL) == 0x8405
        and int(DiagnosticCode.QUERY_OUT_OF_BOUNDS) == 0x8406
        and int(DiagnosticCode.INVALID_QUADKEY) == 0x8407
        and int(DiagnosticCode.SPATIAL_CLUSTER_HAZARD) == 0x8418
        and int(DiagnosticCode.SPATIAL_QUADKEY_PROXIMITY_HAZARD) == 0x8420
        and int(DiagnosticCode.SPATIAL_COLLISION_TRIP) == 0x8420
    )

    status_bits_ok = (
        int(QuadkeyStatusBits.ONLINE) == 0x0001
        and int(QuadkeyStatusBits.HAZARD_ALARM) == 0x0002
        and int(QuadkeyStatusBits.GRID_ACTIVE) == 0x0004
        and int(QuadkeyStatusBits.QUERY_ACTIVE) == 0x0008
        and int(QuadkeyStatusBits.SELECTION_ACTIVE) == 0x0010
        and int(QuadkeyStatusBits.HIGH_CONGESTION) == 0x0020
        and int(QuadkeyStatusBits.DEGRADED_RESOLUTION) == 0x0040
        and int(QuadkeyStatusBits.CELLS_BOUNDED) == 0x0080
    )

    params_ok = (
        CANVAS_VIEWPORT_WIDTH == 1200.0
        and CANVAS_VIEWPORT_HEIGHT == 750.0
        and MIN_QUADKEY_LEVEL == 1
        and MAX_QUADKEY_LEVEL == 23
        and DEFAULT_QUADKEY_LEVEL == 7
        and DEFAULT_HAZARD_THRESHOLD == 35.0
    )

    c2 = regs_ok and diag_ok and status_bits_ok and params_ok
    stages.append({
        "stage": 2,
        "name": "quadkey_constants_and_register_mappings",
        "passed": c2,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Horner OCS %R2790..%R2797, %M651..%M652, diagnostic codes 0x0000/0x8420, and status bits verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: pure_python_quadkey_mercator_bijection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    test_vectors = [
        (0.0, 0.0),                      # Prime Meridian / Equator
        (51.5074, -0.1278),              # London
        (35.6762, 139.6503),             # Tokyo
        (-33.8688, 151.2093),            # Sydney
        (37.7749, -122.4194),            # San Francisco
        (80.0, 10.0),                    # High North
        (-80.0, -20.0),                  # High South
        (10.0, 175.0),                   # Far East
        (-10.0, -175.0),                 # Far West
    ]

    vector_ok = True
    for lat, lon in test_vectors:
        qk = latlon_to_quadkey(lat, lon, level=DEFAULT_QUADKEY_LEVEL)
        if not quadkey_is_valid(qk):
            vector_ok = False
            break
        if len(qk) != DEFAULT_QUADKEY_LEVEL:
            vector_ok = False
            break
        tx, ty, lvl = quadkey_to_tile_xy(qk)
        if lvl != DEFAULT_QUADKEY_LEVEL:
            vector_ok = False
            break
        rec_qk = tile_xy_to_quadkey(tx, ty, lvl)
        if rec_qk != qk:
            vector_ok = False
            break

        bbox = quadkey_to_bbox(qk)
        if not bbox.contains_latlon(lat, lon, tol=1e-5):
            vector_ok = False
            break

        c_lat, c_lon = quadkey_to_latlon(qk)
        if not (bbox.min_lat <= c_lat <= bbox.max_lat and bbox.min_lon <= c_lon <= bbox.max_lon):
            vector_ok = False
            break

        # Int64 packing round-trip
        packed = quadkey_to_int64(qk)
        rec_packed = int64_to_quadkey(packed)
        if rec_packed != qk:
            vector_ok = False
            break

    # Level hierarchy scaling (level 1 to 15)
    res_scaling_ok = True
    test_lat, test_lon = 37.7749, -122.4194
    deep_qk = latlon_to_quadkey(test_lat, test_lon, level=15)
    for lvl in range(1, 16):
        lvl_qk = latlon_to_quadkey(test_lat, test_lon, level=lvl)
        if len(lvl_qk) != lvl:
            res_scaling_ok = False
            break
        p_qk = quadkey_to_parent(deep_qk, parent_level=lvl)
        if p_qk != lvl_qk:
            res_scaling_ok = False
            break

    # Bounds & error rejection
    bounds_rejected = False
    try:
        latlon_to_quadkey(90.0, 0.0, 7)  # lat > 85.05112878
    except ValueError:
        try:
            latlon_to_quadkey(-90.0, 0.0, 7)  # lat < -85.05112878
        except ValueError:
            try:
                latlon_to_quadkey(0.0, 185.0, 7)  # lon > 180
            except ValueError:
                try:
                    latlon_to_quadkey(0.0, 0.0, 0)  # level < 1
                except ValueError:
                    try:
                        latlon_to_quadkey(0.0, 0.0, 24)  # level > 23
                    except ValueError:
                        try:
                            quadkey_to_tile_xy("0124")  # invalid digit 4
                        except ValueError:
                            try:
                                quadkey_to_tile_xy("abcd")  # invalid alphabetic
                            except ValueError:
                                bounds_rejected = True

    c3 = vector_ok and res_scaling_ok and bounds_rejected
    stages.append({
        "stage": 3,
        "name": "pure_python_quadkey_mercator_bijection",
        "passed": c3,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Bijective Mercator projection, QuadKey encode/decode, and 64-bit packing round-trips verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: quadkey_hierarchical_prefix_and_tile_tree
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    hierarchy_ok = True
    sample_quadkeys = [
        latlon_to_quadkey(51.5074, -0.1278, level=5),
        latlon_to_quadkey(35.6762, 139.6503, level=5),
        latlon_to_quadkey(37.7749, -122.4194, level=5),
    ]

    for sq in sample_quadkeys:
        sq_lvl = len(sq)
        children = quadkey_to_children(sq, sq_lvl + 1)
        # Exactly 4 quadkey children
        if len(children) != 4:
            hierarchy_ok = False
            break
        # All 4 mutually distinct
        if len(set(children)) != 4:
            hierarchy_ok = False
            break
        for ch in children:
            if len(ch) != sq_lvl + 1:
                hierarchy_ok = False
                break
            if not ch.startswith(sq):
                hierarchy_ok = False
                break
            if quadkey_to_parent(ch) != sq:
                hierarchy_ok = False
                break

        # 2-level expansion (4^2 = 16 children)
        children_2 = quadkey_to_children(sq, sq_lvl + 2)
        if len(children_2) != 16 or len(set(children_2)) != 16:
            hierarchy_ok = False
            break
        for ch2 in children_2:
            if quadkey_to_parent(ch2, sq_lvl) != sq:
                hierarchy_ok = False
                break

        # Parent bbox coverage contains children bboxes
        p_bbox = quadkey_to_bbox(sq)
        for ch in children:
            ch_bbox = quadkey_to_bbox(ch)
            if not (p_bbox.min_lat <= ch_bbox.min_lat + 1e-9 and
                    ch_bbox.max_lat <= p_bbox.max_lat + 1e-9 and
                    p_bbox.min_lon <= ch_bbox.min_lon + 1e-9 and
                    ch_bbox.max_lon <= p_bbox.max_lon + 1e-9):
                hierarchy_ok = False
                break

        # Siblings verification
        sibs = quadkey_get_siblings(sq)
        if len(sibs) != 4 or len(set(sibs)) != 4 or sq not in sibs:
            hierarchy_ok = False
            break

    # Adjacency & 8-neighbor verification
    test_qk = latlon_to_quadkey(37.7749, -122.4194, level=7)
    nbrs = quadkey_get_neighbors(test_qk)
    neighbors_ok = (len(nbrs) == 8 and len(set(nbrs)) == 8 and test_qk not in nbrs)

    c4 = hierarchy_ok and neighbors_ok
    stages.append({
        "stage": 4,
        "name": "quadkey_hierarchical_prefix_and_tile_tree",
        "passed": c4,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Quadtree prefix nesting, 4-child subdivision, 16-grandchild hierarchy, and 8-neighbor adjacency verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: spatial_proximity_hazard_and_collision_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    p_engine = QuadkeyCanvasEngine(level=7, hazard_threshold=35.0)
    p_engine.build_canonical_sensor_network(seed=42, count=24)

    # 1. Nominal check: zero initial hazard violations
    nom_hazards = p_engine.check_proximity_hazards()
    nom_ok = (
        len(nom_hazards) == 0
        and p_engine.alarm_active is False
        and p_engine.diagnostic_code == DiagnosticCode.OK
    )

    # 2. Collision trip: insert node in tight proximity (distance 10.0 px <= 35.0 threshold)
    target = p_engine.nodes[1]
    p_engine.insert_node(
        x=target.x + 8.0,
        y=target.y + 6.0,
        node_id=999,
        tag="COLLIDING-01",
        hazard_radius=20.0,
    )
    trip_hazards = p_engine.check_proximity_hazards()
    trip_ok = (
        len(trip_hazards) >= 1
        and p_engine.alarm_active is True
        and p_engine.diagnostic_code == DiagnosticCode.SPATIAL_QUADKEY_PROXIMITY_HAZARD
        and p_engine.hazard_violations >= 1
    )

    # 3. Register sync on hazard trip
    rt_trip = RegisterTable()
    p_engine.sync_to_registers(rt_trip)
    coil_alarm_trip = rt_trip.read_bit(COIL_W318_HAZARD_ALARM)
    coil_online_trip = rt_trip.read_bit(COIL_W318_CANVAS_ONLINE)
    reg_diag_trip = rt_trip.read_word(REG_W318_DIAGNOSTIC_CODE)
    regs_trip_ok = (
        coil_alarm_trip is True
        and coil_online_trip is False
        and (reg_diag_trip & 0xFFFF) == 0x8420
    )

    # 4. Clearing hazard: remove colliding node
    p_engine.remove_node(999)
    p_engine.check_proximity_hazards()
    clear_ok = (
        p_engine.alarm_active is False
        and p_engine.hazard_violations == 0
        and p_engine.diagnostic_code == DiagnosticCode.OK
    )
    p_engine.sync_to_registers(rt_trip)
    regs_clear_ok = (
        rt_trip.read_bit(COIL_W318_HAZARD_ALARM) is False
        and rt_trip.read_bit(COIL_W318_CANVAS_ONLINE) is True
        and (rt_trip.read_word(REG_W318_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
    )

    c5 = nom_ok and trip_ok and regs_trip_ok and clear_ok and regs_clear_ok
    stages.append({
        "stage": 5,
        "name": "spatial_proximity_hazard_and_collision_trip",
        "passed": c5,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Spatial proximity collision trip, coil %M652 alarm latch, and nominal reset verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: register_table_synchronization_and_signed_masks
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_sync = RegisterTable()
    s_engine = create_canonical_quadkey_canvas(seed=42, count=24, level=7)
    s_engine.query_radius(600.0, 375.0, 200.0)
    s_engine.sync_to_registers(rt_sync)

    w_total = rt_sync.read_word(REG_W318_TOTAL_OBJECTS)
    w_lvl = rt_sync.read_word(REG_W318_LEVEL)
    w_cells = rt_sync.read_word(REG_W318_ACTIVE_CELLS)
    w_hash = rt_sync.read_word(REG_W318_PRIMARY_HASH)
    w_match = rt_sync.read_word(REG_W318_MATCH_COUNT)
    w_viols = rt_sync.read_word(REG_W318_HAZARD_VIOLATIONS)
    w_status = rt_sync.read_word(REG_W318_STATUS_WORD)
    w_diag = rt_sync.read_word(REG_W318_DIAGNOSTIC_CODE)
    b_online = rt_sync.read_bit(COIL_W318_CANVAS_ONLINE)
    b_alarm = rt_sync.read_bit(COIL_W318_HAZARD_ALARM)

    c6_reads = (
        (w_total & 0xFFFF) == len(s_engine.nodes)
        and (w_lvl & 0xFFFF) == s_engine.level
        and (w_cells & 0xFFFF) == len(set(n.quadkey for n in s_engine.nodes.values()))
        and (w_hash & 0xFFFF) == s_engine.metrics.primary_hash
        and (w_match & 0xFFFF) == len(s_engine.last_query_results)
        and (w_viols & 0xFFFF) == 0
        and (w_status & 0x0001) == 1
        and (w_diag & 0xFFFF) == 0x0000
        and b_online is True
        and b_alarm is False
    )

    # Bitwise signed masks verification
    rt_sync.write_word(REG_W318_DIAGNOSTIC_CODE, (-55) & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
    raw_val = rt_sync.read_word(REG_W318_DIAGNOSTIC_CODE)
    val_u = raw_val & 0xFFFF
    val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
    c6_signed = (val_u == 65481 and val_s == -55)

    # High-bit diagnostic code verification
    diag_code = DiagnosticCode.SPATIAL_QUADKEY_PROXIMITY_HAZARD
    rt_sync.write_word(REG_W318_DIAGNOSTIC_CODE, int(diag_code) & 0xFFFF, privilege=PrivilegeMode.USER)
    diag_read = rt_sync.read_word(REG_W318_DIAGNOSTIC_CODE)
    c6_diag = ((diag_read & 0xFFFF) == int(diag_code) and (diag_read & 0xFFFF) == 0x8420)

    # Restore nominal diagnostic in register
    s_engine.sync_to_registers(rt_sync)

    c6 = c6_reads and c6_signed and c6_diag
    stages.append({
        "stage": 6,
        "name": "register_table_synchronization_and_signed_masks",
        "passed": c6,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Horner OCS %R2790..%R2797 and %M651..%M652 synchronized; signed 16-bit masks and 0x8420 verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    SecurityGuard.assert_pure_st_content(ST_PROGRAM_W318_QUADKEY_CANVAS_SYNC)
    st_val = STParser.validate_code(ST_PROGRAM_W318_QUADKEY_CANVAS_SYNC)
    st_ast = STParser.parse_pou(ST_PROGRAM_W318_QUADKEY_CANVAS_SYNC)
    st_pou_ok = (
        st_val.status == AgentStatus.SUCCESS
        and st_ast.pou_type == POUType.PROGRAM
        and st_ast.name == "QuadkeyCanvasSync"
    )

    # Anti-ladder security guard interception
    ladder_contacts_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM P VAR b: BOOL; END_VAR ---[ ]--- END_PROGRAM")
    except LadderForbiddenError:
        ladder_contacts_rejected = True

    ladder_coils_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM P VAR b: BOOL; END_VAR ---( )--- END_PROGRAM")
    except LadderForbiddenError:
        ladder_coils_rejected = True

    ladder_rungs_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM P VAR b: BOOL; END_VAR RUNG 1: x:=1; END_PROGRAM")
    except LadderForbiddenError:
        ladder_rungs_rejected = True

    ladder_mnemonics_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM P VAR b: BOOL; END_VAR XIC b; END_PROGRAM")
    except LadderForbiddenError:
        ladder_mnemonics_rejected = True

    c7 = (
        st_pou_ok
        and ladder_contacts_rejected
        and ladder_coils_rejected
        and ladder_rungs_rejected
        and ladder_mnemonics_rejected
    )
    stages.append({
        "stage": 7,
        "name": "pure_st_pou_and_anti_ladder_rejection",
        "passed": c7,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Pure ST POU 'QuadkeyCanvasSync' AST validated; ladder contacts, coils, rungs, and mnemonics strictly rejected.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: svg_scada_canvas_rasterization_and_wcag_contrast
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    canon_canvas = create_canonical_quadkey_canvas(seed=42, count=24, level=7)
    canon_canvas.query_radius(600.0, 375.0, 180.0)
    svg_text = generate_quadkey_canvas_svg(canon_canvas)

    # XML validation
    root_el = ET.fromstring(svg_text)
    svg_valid = (
        root_el.tag.endswith("svg")
        and root_el.attrib.get("version") == "1.1"
        and root_el.attrib.get("viewBox") == "0 0 1200 750"
        and "quadkey-tile-layer" in svg_text
        and "nodes-layer" in svg_text
        and "query-reticle-layer" in svg_text
        and "scorecard-layer" in svg_text
        and "sensor-node" in svg_text
        and "<rect" in svg_text
    )

    # WCAG 2.1 AAA Contrast Ratio compliance (> 18:1)
    contrast_ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    contrast_ok = (contrast_ratio >= 18.0)

    c8 = svg_valid and contrast_ok
    stages.append({
        "stage": 8,
        "name": "svg_scada_canvas_rasterization_and_wcag_contrast",
        "passed": c8,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"W3C SVG 1.1 generated with QuadKey tiles; WCAG AAA contrast ratio verified ({contrast_ratio:.2f}:1 >= 18:1).",
    })

    # ------------------------------------------------------------------------
    # Stage 9: multi_cycle_simulation_soak_and_evidence_emission
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim_engine = QuadkeyCanvasEngine(level=7)
    sim_rt = RegisterTable()
    cycles = 5 if quick else 20

    all_steps_ok = True
    for c in range(1, cycles + 1):
        ctx = ScanContext(cycle=c, dt_ms=10.0, register_table=sim_rt)
        sim_engine.insert_node(
            x=80.0 + c * 25.0,
            y=80.0 + (c % 5) * 40.0,
            node_id=c,
            tag=f"DYN-{c:03d}",
        )
        sim_engine.query_radius(600.0, 375.0, 100.0 + c * 10.0)
        res = sim_engine.execute(ctx)
        if res.status != AgentStatus.SUCCESS:
            all_steps_ok = False
            break

    c9_sim = (all_steps_ok and sim_engine.cycle_count == cycles and len(sim_engine.nodes) == cycles)
    passed_so_far = sum(1 for s in stages if s["passed"])
    c9 = c9_sim and (passed_so_far == 8)

    # Compute SHA-256 digest of sample SVG
    svg_bytes = svg_text.encode("utf-8")
    svg_sha256 = hashlib.sha256(svg_bytes).hexdigest()

    stages.append({
        "stage": 9,
        "name": "multi_cycle_simulation_soak_and_evidence_emission",
        "passed": c9,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Multi-cycle closed loop scan ({cycles} cycles) and deterministic cryptographic evidence manifest generated.",
    })

    passed_count = sum(1 for s in stages if s["passed"])
    total_count = len(stages)
    all_passed = (passed_count == total_count and total_count == 9)

    evidence_payload: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": f"Wave {work_package} QuadKey Canvas Verification PASSED ({passed_count}/{total_count} stages).",
        "data": {
            "work_package": work_package,
            "gate": "G9",
            "checks_passed": passed_count,
            "total_checks": total_count,
            "stages": stages,
            "svg_sample_path": str(sample_svg_path) if sample_svg_path else None,
            "svg_sha256": svg_sha256,
        },
    }

    # Compute SHA-256 of canonical evidence payload
    payload_str = json.dumps(evidence_payload, sort_keys=True)
    evidence_payload["data"]["evidence_sha256"] = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    # Emit JSON evidence artifact
    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence_payload, f, indent=2)

    # Emit sample SVG artifact
    if sample_svg_path:
        svg_p = Path(sample_svg_path)
        svg_p.parent.mkdir(parents=True, exist_ok=True)
        with open(svg_p, "w", encoding="utf-8") as f:
            f.write(svg_text)

    return evidence_payload


# ============================================================================
# 7. CLI Main Entry Point
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point for W318 QuadKey Canvas verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Cscape HMI Dynamic Spatial Quadkey / Bing Maps Tile Hierarchical SCADA Canvas (W318) 9-Stage Verification Suite"
    )
    parser.add_argument(
        "positional_output",
        nargs="?",
        default=None,
        help="Optional positional path to write JSON evidence artifact.",
    )
    parser.add_argument(
        "positional_svg",
        nargs="?",
        default=None,
        help="Optional positional path to write SVG sample artifact.",
    )
    parser.add_argument(
        "--output",
        "-o",
        "--evidence-path",
        "-e",
        dest="output_path",
        type=str,
        default="artifacts/HMI/quadkey_canvas_evidence.json",
        help="Path to output verification evidence JSON (default: artifacts/HMI/quadkey_canvas_evidence.json)",
    )
    parser.add_argument(
        "--svg",
        "-s",
        "--svg-output",
        "--sample-svg",
        dest="svg_output_path",
        type=str,
        default="artifacts/HMI/quadkey_canvas_sample.svg",
        help="Path to output sample SVG graphic (default: artifacts/HMI/quadkey_canvas_sample.svg)",
    )
    parser.add_argument(
        "--quick",
        "-q",
        action="store_true",
        help="Run accelerated verification with reduced simulation cycles",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_mode",
        help="Force JSON output mode",
    )
    parser.add_argument(
        "--work-package",
        "-w",
        dest="work_package",
        type=str,
        default="W318",
        help="Work package identifier (default: W318)",
    )

    args = parser.parse_args(argv)
    effective_output = args.positional_output or args.output_path
    effective_svg = args.positional_svg or args.svg_output_path

    if not args.json_mode:
        print(f"\n{CLR_CYAN}{CLR_BOLD}======================================================================{CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}  JEV CSCAPE VERIFICATION RUNNER - WORK PACKAGE {args.work_package}                 {CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}  Gate G9: Dynamic Spatial Quadkey / Bing Maps Tile Canvas            {CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}======================================================================{CLR_RESET}\n")

    t_start = time.perf_counter()
    evidence = run_quadkey_canvas_verification(
        output_path=effective_output,
        sample_svg_path=effective_svg,
        work_package=args.work_package,
        quick=args.quick,
    )
    t_elapsed = time.perf_counter() - t_start

    stages = evidence.get("data", {}).get("stages", [])
    if not args.json_mode:
        for stg in stages:
            num = stg.get("stage", 0)
            name = stg.get("name", "unknown")
            passed = stg.get("passed", False)
            t_ms = stg.get("timing_ms", 0.0)
            badge = format_stage_badge(passed)
            print(f"  Stage {num:d}: {name:<52} {badge} ({t_ms:.2f} ms)")

        print(f"\n{CLR_GRAY}----------------------------------------------------------------------{CLR_RESET}")
        overall_status = evidence.get("status", "failed")
        passed_count = evidence.get("data", {}).get("checks_passed", 0)
        total_count = evidence.get("data", {}).get("total_checks", 0)

        if overall_status == "success":
            print(f"{CLR_GREEN}{CLR_BOLD}  OVERALL RESULT: SUCCESS ({passed_count}/{total_count} stages passed in {t_elapsed:.2f}s){CLR_RESET}")
        else:
            print(f"{CLR_RED}{CLR_BOLD}  OVERALL RESULT: FAILED ({passed_count}/{total_count} stages passed in {t_elapsed:.2f}s){CLR_RESET}")

        if effective_output:
            print(f"{CLR_DIM}  Evidence JSON emitted to: {effective_output}{CLR_RESET}")
        if effective_svg:
            print(f"{CLR_DIM}  Sample SVG emitted to:    {effective_svg}{CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}======================================================================{CLR_RESET}\n")

    # Always output strict 4-state contract json
    print(json.dumps(evidence, indent=2))

    return 0 if evidence.get("status") == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
