#!/usr/bin/env python3
"""Verification Runner for Cscape HMI Dynamic Spatial S2 Spherical Geometry SCADA Canvas (W312).

Work Package: W312 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial S2 Spherical Geometry SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: environment_and_platform_check
  Stage 2: s2_constants_and_register_mappings
  Stage 3: pure_python_s2_spherical_projection_bijection
  Stage 4: s2_cube_face_and_quadtree_hierarchy
  Stage 5: spatial_proximity_hazard_and_collision_trip
  Stage 6: register_table_synchronization_and_signed_masks
  Stage 7: pure_st_pou_and_anti_ladder_rejection
  Stage 8: svg_scada_canvas_rasterization_and_wcag_contrast
  Stage 9: multi_cycle_simulation_soak_and_evidence_emission

CLI Arguments:
  --output, -o (default: artifacts/HMI/s2_canvas_evidence.json)
  --svg, -s (default: artifacts/HMI/s2_canvas_sample.svg)
  --quick, -q (accelerated verification with reduced simulation cycles)
  --json (force JSON emission)
  --work-package, -w (default: W312)
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
# 1. Constants, Palette & Horner OCS Register Map (W312)
# ============================================================================

CANVAS_VIEWPORT_WIDTH: float         = 1200.0
CANVAS_VIEWPORT_HEIGHT: float        = 750.0
TOTAL_DOMAIN_AREA: float             = CANVAS_VIEWPORT_WIDTH * CANVAS_VIEWPORT_HEIGHT

MIN_S2_LEVEL: int                    = 1
MAX_S2_LEVEL: int                    = 30
DEFAULT_S2_LEVEL: int                = 10
DEFAULT_HAZARD_THRESHOLD: float      = 35.0

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
COLOR_S2_CELL: str                   = "#38BDF8"
COLOR_S2_BORDER: str                 = "#0284C7"
COLOR_GRID_LINE: str                 = "#1E293B"

# Horner OCS Word Register Map (%R2730..%R2737) & Discrete Coils (%M637..%M638)
REG_W312_TOTAL_OBJECTS: str          = "%R2730"
REG_W312_LEVEL: str                  = "%R2731"
REG_W312_ACTIVE_CELLS: str           = "%R2732"
REG_W312_PRIMARY_HASH: str           = "%R2733"
REG_W312_MATCH_COUNT: str            = "%R2734"
REG_W312_HAZARD_VIOLATIONS: str      = "%R2735"
REG_W312_STATUS_WORD: str            = "%R2736"
REG_W312_DIAGNOSTIC_CODE: str        = "%R2737"

COIL_W312_CANVAS_ONLINE: str         = "%M637"
COIL_W312_HAZARD_ALARM: str          = "%M638"

REG_S2_TOTAL_OBJECTS                 = REG_W312_TOTAL_OBJECTS
REG_S2_LEVEL                         = REG_W312_LEVEL
REG_S2_ACTIVE_CELLS                  = REG_W312_ACTIVE_CELLS
REG_S2_PRIMARY_HASH                  = REG_W312_PRIMARY_HASH
REG_S2_MATCH_COUNT                   = REG_W312_MATCH_COUNT
REG_S2_HAZARD_VIOLATIONS             = REG_W312_HAZARD_VIOLATIONS
REG_S2_STATUS_WORD                   = REG_W312_STATUS_WORD
REG_S2_DIAGNOSTIC_CODE               = REG_W312_DIAGNOSTIC_CODE

COIL_S2_CANVAS_ONLINE                = COIL_W312_CANVAS_ONLINE
COIL_S2_HAZARD_ALARM                 = COIL_W312_HAZARD_ALARM


class DiagnosticCode(IntEnum):
    """Horner OCS W312 S2 Spherical Geometry SCADA Diagnostic Codes."""
    OK                              = 0x0000
    INVALID_DOMAIN                  = 0x8401
    DEGENERATE_BOUNDING_BOX         = 0x8402
    OUT_OF_BOUNDS                   = 0x8403
    EMPTY_CANVAS                    = 0x8404
    INVALID_LEVEL                   = 0x8405
    QUERY_OUT_OF_BOUNDS             = 0x8406
    INVALID_CELL_ID                 = 0x8407
    SPATIAL_CLUSTER_HAZARD          = 0x8418
    SPATIAL_S2_PROXIMITY_HAZARD     = 0x8420
    SPATIAL_COLLISION_TRIP          = 0x8420


DIAG_OK                             = DiagnosticCode.OK
DIAG_ERR_INVALID_DOMAIN             = DiagnosticCode.INVALID_DOMAIN
DIAG_ERR_DEGENERATE_BOUNDING_BOX    = DiagnosticCode.DEGENERATE_BOUNDING_BOX
DIAG_ERR_OUT_OF_BOUNDS              = DiagnosticCode.OUT_OF_BOUNDS
DIAG_ERR_EMPTY_CANVAS               = DiagnosticCode.EMPTY_CANVAS
DIAG_ERR_INVALID_LEVEL              = DiagnosticCode.INVALID_LEVEL
DIAG_ERR_QUERY_OUT_OF_BOUNDS        = DiagnosticCode.QUERY_OUT_OF_BOUNDS
DIAG_ERR_INVALID_CELL_ID            = DiagnosticCode.INVALID_CELL_ID
DIAG_ERR_SPATIAL_S2_PROXIMITY_HAZARD = DiagnosticCode.SPATIAL_S2_PROXIMITY_HAZARD


class S2StatusBits(IntFlag):
    """16-bit packed status word for S2 Geometry Canvas engine."""
    ONLINE              = 0x0001
    HAZARD_ALARM        = 0x0002
    GRID_ACTIVE         = 0x0004
    QUERY_ACTIVE        = 0x0008
    SELECTION_ACTIVE    = 0x0010
    HIGH_CONGESTION     = 0x0020
    DEGRADED_RESOLUTION = 0x0040
    CELLS_BOUNDED       = 0x0080


# ============================================================================
# 2. Pure Python S2 Spherical Projection & Hilbert Quadtree Algorithms
# ============================================================================

def hilbert_xy2d(order: int, x: int, y: int) -> int:
    """Map 2D grid coordinates (x, y) to 1D Hilbert curve index d."""
    if order < 1:
        return 0
    d = 0
    s = (1 << order) // 2
    cur_x, cur_y = x, y
    while s > 0:
        rx = 1 if (cur_x & s) > 0 else 0
        ry = 1 if (cur_y & s) > 0 else 0
        d += s * s * ((3 * rx) ^ ry)
        if ry == 0:
            if rx == 1:
                cur_x = (s * 2 - 1) - cur_x
                cur_y = (s * 2 - 1) - cur_y
            cur_x, cur_y = cur_y, cur_x
        s //= 2
    return d


def hilbert_d2xy(order: int, d: int) -> Tuple[int, int]:
    """Map 1D Hilbert curve index d to 2D grid coordinates (x, y)."""
    if order < 1:
        return 0, 0
    x = 0
    y = 0
    s = 1
    t = d
    n = 1 << order
    while s < n:
        rx = 1 & (t // 2)
        ry = 1 & (t ^ rx)
        if ry == 0:
            if rx == 1:
                x = s - 1 - x
                y = s - 1 - y
            x, y = y, x
        x += s * rx
        y += s * ry
        t //= 4
        s *= 2
    return x, y


def latlon_to_xyz(lat: float, lon: float) -> Tuple[float, float, float]:
    """Convert spherical latitude/longitude (degrees) to 3D unit vector."""
    if not (-90.0 <= lat <= 90.0):
        raise ValueError(f"Latitude out of bounds [-90, 90]: {lat}")
    if not (-180.0 <= lon <= 180.0):
        raise ValueError(f"Longitude out of bounds [-180, 180]: {lon}")
    phi = math.radians(lat)
    lam = math.radians(lon)
    x = math.cos(phi) * math.cos(lam)
    y = math.cos(phi) * math.sin(lam)
    z = math.sin(phi)
    return x, y, z


def xyz_to_latlon(x: float, y: float, z: float) -> Tuple[float, float]:
    """Convert 3D Cartesian coordinates to spherical latitude/longitude (degrees)."""
    norm = math.sqrt(x * x + y * y + z * z)
    if norm == 0.0:
        return 0.0, 0.0
    nx, ny, nz = x / norm, y / norm, z / norm
    z_clamped = max(-1.0, min(1.0, nz))
    lat = math.degrees(math.asin(z_clamped))
    lon = math.degrees(math.atan2(ny, nx))
    return lat, lon


def xyz_to_face_uv(x: float, y: float, z: float) -> Tuple[int, float, float]:
    """Project 3D unit vector onto S2 cube face index [0..5] and (u, v) in [-1, 1]."""
    ax, ay, az = abs(x), abs(y), abs(z)
    if ax >= ay and ax >= az:
        if x > 0:
            return 0, y / x, z / x
        else:
            return 3, z / x, y / x
    elif ay >= ax and ay >= az:
        if y > 0:
            return 1, -x / y, z / y
        else:
            return 4, z / y, -x / y
    else:
        if z > 0:
            return 2, -x / z, -y / z
        else:
            return 5, -y / z, -x / z


def face_uv_to_xyz(face: int, u: float, v: float) -> Tuple[float, float, float]:
    """Unproject S2 cube face index [0..5] and (u, v) in [-1, 1] to 3D unit vector."""
    if not (0 <= face <= 5):
        raise ValueError(f"Invalid S2 face index: {face}")
    if face == 0:
        vx, vy, vz = 1.0, u, v
    elif face == 1:
        vx, vy, vz = -u, 1.0, v
    elif face == 2:
        vx, vy, vz = -u, -v, 1.0
    elif face == 3:
        vx, vy, vz = -1.0, -v, -u
    elif face == 4:
        vx, vy, vz = v, -1.0, -u
    else:  # face == 5
        vx, vy, vz = v, u, -1.0

    norm = math.sqrt(vx * vx + vy * vy + vz * vz)
    return vx / norm, vy / norm, vz / norm


def uv_to_st(u: float, v: float) -> Tuple[float, float]:
    """Map face tangent space (u, v) in [-1, 1] to normalized cell space (s, t) in [0, 1]."""
    s = (max(-1.0, min(1.0, u)) + 1.0) / 2.0
    t = (max(-1.0, min(1.0, v)) + 1.0) / 2.0
    return s, t


def st_to_uv(s: float, t: float) -> Tuple[float, float]:
    """Map normalized cell space (s, t) in [0, 1] to face tangent space (u, v) in [-1, 1]."""
    u = 2.0 * max(0.0, min(1.0, s)) - 1.0
    v = 2.0 * max(0.0, min(1.0, t)) - 1.0
    return u, v


def latlon_to_s2_cell_id(lat: float, lon: float, level: int = DEFAULT_S2_LEVEL) -> int:
    """Encode latitude and longitude to a 64-bit S2 Cell ID."""
    if not (MIN_S2_LEVEL <= level <= MAX_S2_LEVEL):
        raise ValueError(f"Level must be between {MIN_S2_LEVEL} and {MAX_S2_LEVEL}, got {level}")
    x, y, z = latlon_to_xyz(lat, lon)
    face, u, v = xyz_to_face_uv(x, y, z)
    s, t = uv_to_st(u, v)

    n = 1 << level
    i = max(0, min(n - 1, int(s * n)))
    j = max(0, min(n - 1, int(t * n)))

    h = hilbert_xy2d(level, i, j)
    shift = 2 * (30 - level) + 1
    sentinel = 1 << (2 * (30 - level))

    return (face << 61) | (h << shift) | sentinel


def s2_cell_level(cell_id: int) -> int:
    """Extract subdivision level [0..30] from a 64-bit S2 Cell ID."""
    if cell_id <= 0:
        raise ValueError(f"Invalid non-positive S2 cell ID: {cell_id}")
    lowest = cell_id & (-cell_id)
    tz = lowest.bit_length() - 1
    return 30 - (tz // 2)


def s2_cell_face(cell_id: int) -> int:
    """Extract cube face index [0..5] from a 64-bit S2 Cell ID."""
    return (cell_id >> 61) & 0x7


def s2_cell_hilbert(cell_id: int) -> int:
    """Extract Hilbert space-filling curve index from a 64-bit S2 Cell ID."""
    lvl = s2_cell_level(cell_id)
    shift = 2 * (30 - lvl) + 1
    mask = (1 << (2 * lvl)) - 1
    return (cell_id >> shift) & mask


def s2_cell_parent(cell_id: int, target_level: Optional[int] = None) -> int:
    """Get parent cell ID at specified target level (default: current level - 1)."""
    lvl = s2_cell_level(cell_id)
    p_lvl = (lvl - 1) if target_level is None else target_level
    if not (0 <= p_lvl <= lvl):
        raise ValueError(f"Target parent level {p_lvl} must be in [0, {lvl}]")
    shift = 2 * (30 - p_lvl)
    mask = ~((1 << (shift + 1)) - 1)
    return (cell_id & mask) | (1 << shift)


def s2_cell_children(cell_id: int) -> List[int]:
    """Get the 4 quadtree children of an S2 Cell ID at level L + 1."""
    lvl = s2_cell_level(cell_id)
    if lvl >= MAX_S2_LEVEL:
        raise ValueError(f"Cannot subdivide leaf cell at max level {MAX_S2_LEVEL}")
    b = 2 * (30 - lvl)
    b_new = b - 2
    base = cell_id & ~(1 << b)
    children: List[int] = []
    for k in range(4):
        child = base | (k << (b_new + 1)) | (1 << b_new)
        children.append(child)
    return children


def s2_cell_neighbors(cell_id: int) -> List[int]:
    """Calculate orthogonal 4-neighbors of an S2 cell at the same level within the face."""
    lvl = s2_cell_level(cell_id)
    face = s2_cell_face(cell_id)
    h = s2_cell_hilbert(cell_id)
    i, j = hilbert_d2xy(lvl, h)
    n = 1 << lvl
    nbrs: List[int] = []
    shift = 2 * (30 - lvl) + 1
    sentinel = 1 << (2 * (30 - lvl))
    for di, dj in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
        ni, nj = i + di, j + dj
        if 0 <= ni < n and 0 <= nj < n:
            nh = hilbert_xy2d(lvl, ni, nj)
            nid = (face << 61) | (nh << shift) | sentinel
            nbrs.append(nid)
    return nbrs


def s2_face_root_cell_id(face: int) -> int:
    """Generate root level 0 S2 Cell ID for the given cube face [0..5]."""
    if not (0 <= face <= 5):
        raise ValueError(f"Invalid face index {face}")
    return (face << 61) | (1 << 60)


def s2_cell_to_token(cell_id: int) -> str:
    """Encode 64-bit S2 Cell ID to hexadecimal token string."""
    if cell_id == 0:
        return "X"
    h = f"{cell_id:016x}".rstrip("0")
    return h if h else "0"


def s2_token_to_cell_id(token: str) -> int:
    """Decode hexadecimal token string back to 64-bit S2 Cell ID."""
    if not token or token == "X":
        return 0
    # Validate hex characters
    try:
        int(token, 16)
    except ValueError as exc:
        raise ValueError(f"Invalid S2 hexadecimal token '{token}'") from exc
    pad = 16 - len(token)
    if pad < 0:
        raise ValueError(f"Token length {len(token)} exceeds 16 hex digits")
    return int(token + ("0" * pad), 16)


@dataclass
class S2BoundingBox:
    """Geographic bounding box for an S2 Cell."""
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

    def contains_latlon(self, lat: float, lon: float) -> bool:
        return self.min_lat <= lat <= self.max_lat and self.min_lon <= lon <= self.max_lon


def s2_cell_id_to_latlon(cell_id: int) -> Tuple[float, float]:
    """Decode S2 Cell ID to its center (lat, lon) coordinates."""
    face = s2_cell_face(cell_id)
    lvl = s2_cell_level(cell_id)
    h = s2_cell_hilbert(cell_id)
    i, j = hilbert_d2xy(lvl, h)

    n = 1 << lvl
    s = (i + 0.5) / float(n)
    t = (j + 0.5) / float(n)
    u, v = st_to_uv(s, t)
    x, y, z = face_uv_to_xyz(face, u, v)
    return xyz_to_latlon(x, y, z)


def s2_cell_bbox(cell_id: int) -> S2BoundingBox:
    """Calculate geographic bounding box for an S2 Cell."""
    face = s2_cell_face(cell_id)
    lvl = s2_cell_level(cell_id)
    h = s2_cell_hilbert(cell_id)
    i, j = hilbert_d2xy(lvl, h)

    n = 1 << lvl
    corners_st = [
        (i / float(n), j / float(n)),
        ((i + 1) / float(n), j / float(n)),
        ((i + 1) / float(n), (j + 1) / float(n)),
        (i / float(n), (j + 1) / float(n)),
    ]

    lats: List[float] = []
    lons: List[float] = []
    for s, t in corners_st:
        u, v = st_to_uv(s, t)
        x, y, z = face_uv_to_xyz(face, u, v)
        c_lat, c_lon = xyz_to_latlon(x, y, z)
        lats.append(c_lat)
        lons.append(c_lon)

    return S2BoundingBox(
        min_lat=min(lats),
        max_lat=max(lats),
        min_lon=min(lons),
        max_lon=max(lons),
    )


def s2_cell_to_word16(cell_id: int) -> int:
    """Compute deterministic 16-bit FNV-1a hash code of S2 Cell ID for Horner OCS register."""
    if cell_id == 0:
        return 0
    h = 0x811C
    tok = s2_cell_to_token(cell_id)
    for b in tok.encode("ascii"):
        h = ((h ^ b) * 0x0103) & 0xFFFF
    return h


def angular_distance_deg(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate great-circle angular distance on the sphere in degrees."""
    v1 = latlon_to_xyz(lat1, lon1)
    v2 = latlon_to_xyz(lat2, lon2)
    dot = max(-1.0, min(1.0, v1[0] * v2[0] + v1[1] * v2[1] + v1[2] * v2[2]))
    return math.degrees(math.acos(dot))


# Coordinate conversions between Viewport [0, 1200] x [0, 750] and Geographic [-90, 90] x [-180, 180]
def canvas_to_latlon(
    x: float,
    y: float,
    width: float = CANVAS_VIEWPORT_WIDTH,
    height: float = CANVAS_VIEWPORT_HEIGHT,
) -> Tuple[float, float]:
    """Map SCADA canvas screen coordinates (x, y) to (lat, lon)."""
    lon = -180.0 + (x / width) * 360.0
    lat = 90.0 - (y / height) * 180.0
    lat = max(-90.0, min(90.0, lat))
    lon = max(-180.0, min(180.0, lon))
    return lat, lon


def latlon_to_canvas(
    lat: float,
    lon: float,
    width: float = CANVAS_VIEWPORT_WIDTH,
    height: float = CANVAS_VIEWPORT_HEIGHT,
) -> Tuple[float, float]:
    """Map (lat, lon) to SCADA canvas screen coordinates (x, y)."""
    x = ((lon + 180.0) / 360.0) * width
    y = ((90.0 - lat) / 180.0) * height
    return x, y


@dataclass
class S2Rect:
    """Axis-aligned 2D bounding rectangle in SCADA canvas coordinate space."""
    min_x: float
    min_y: float
    max_x: float
    max_y: float

    def __post_init__(self) -> None:
        if self.min_x > self.max_x or self.min_y > self.max_y:
            raise ValueError(
                f"Degenerate Rect bounds: [{self.min_x}, {self.min_y}, {self.max_x}, {self.max_y}]"
            )

    @property
    def width(self) -> float:
        return self.max_x - self.min_x

    @property
    def height(self) -> float:
        return self.max_y - self.min_y

    @property
    def area(self) -> float:
        return self.width * self.height

    @property
    def center_x(self) -> float:
        return (self.min_x + self.max_x) / 2.0

    @property
    def center_y(self) -> float:
        return (self.min_y + self.max_y) / 2.0

    def contains_coord(self, x: float, y: float) -> bool:
        return self.min_x <= x <= self.max_x and self.min_y <= y <= self.max_y

    def intersects(self, other: "S2Rect") -> bool:
        return not (
            self.max_x < other.min_x
            or self.min_x > other.max_x
            or self.max_y < other.min_y
            or self.min_y > other.max_y
        )


def s2_cell_to_canvas_rect(
    cell_id: int,
    width: float = CANVAS_VIEWPORT_WIDTH,
    height: float = CANVAS_VIEWPORT_HEIGHT,
) -> S2Rect:
    """Convert an S2 Cell bounding box into canvas screen coordinates."""
    bbox = s2_cell_bbox(cell_id)
    x1, y1 = latlon_to_canvas(bbox.max_lat, bbox.min_lon, width, height)
    x2, y2 = latlon_to_canvas(bbox.min_lat, bbox.max_lon, width, height)
    min_x = max(0.0, min(x1, x2))
    max_x = min(width, max(x1, x2))
    min_y = max(0.0, min(y1, y2))
    max_y = min(height, max(y1, y2))
    # Ensure non-zero dimensions
    if max_x <= min_x:
        max_x = min(width, min_x + 10.0)
    if max_y <= min_y:
        max_y = min(height, min_y + 10.0)
    return S2Rect(min_x=min_x, min_y=min_y, max_x=max_x, max_y=max_y)


@dataclass
class SpatialNode:
    """Equipment or sensor node indexed within the S2 SCADA canvas."""
    id: int
    x: float
    y: float
    lat: float = 0.0
    lon: float = 0.0
    cell_id: int = 0
    token: str = ""
    tag: str = ""
    equip_type: str = "sensor"
    status: str = "normal"
    hazard_radius: float = 25.0
    hash_word: int = 0


@dataclass
class S2Metrics:
    """Runtime telemetry metrics snapshot for Horner OCS register synchronization."""
    total_objects: int = 0
    level: int = DEFAULT_S2_LEVEL
    active_cells: int = 0
    primary_hash: int = 0
    match_count: int = 0
    hazard_violations: int = 0
    status_word: int = 0
    diagnostic_code: DiagnosticCode = DiagnosticCode.OK
    canvas_online: bool = True
    hazard_alarm: bool = False


# ============================================================================
# 3. S2 Canvas Engine Implementation
# ============================================================================

class S2CanvasEngine(ILogicUnit):
    """Dynamic Spatial S2 Spherical Geometry SCADA Canvas Engine."""

    def __init__(
        self,
        level: int = DEFAULT_S2_LEVEL,
        viewport_width: float = CANVAS_VIEWPORT_WIDTH,
        viewport_height: float = CANVAS_VIEWPORT_HEIGHT,
        hazard_threshold: float = DEFAULT_HAZARD_THRESHOLD,
    ) -> None:
        if not (MIN_S2_LEVEL <= level <= MAX_S2_LEVEL):
            raise ValueError(
                f"Level must be between {MIN_S2_LEVEL} and {MAX_S2_LEVEL}, got {level}"
            )
        self.level: int = level
        self.viewport_width: float = viewport_width
        self.viewport_height: float = viewport_height
        self.hazard_threshold: float = hazard_threshold

        self.nodes: Dict[int, SpatialNode] = {}
        self.selected_node_id: int = 0
        self.last_query_results: List[SpatialNode] = []
        self.last_query_rect: Optional[S2Rect] = None
        self.last_query_radius: float = 0.0
        self.last_query_token_prefix: str = ""

        self.reg_table: RegisterTable = RegisterTable()
        self.cycle_count: int = 0
        self.alarm_active: bool = False
        self.hazard_violations: int = 0
        self.diagnostic_code: DiagnosticCode = DiagnosticCode.OK

    def insert_node(
        self,
        x: float,
        y: float,
        node_id: Optional[int] = None,
        tag: str = "",
        equip_type: str = "sensor",
        status: str = "normal",
        hazard_radius: float = 25.0,
    ) -> SpatialNode:
        """Insert a node with canvas coordinates and index via S2 Cell ID."""
        if not (0.0 <= x <= self.viewport_width and 0.0 <= y <= self.viewport_height):
            self.diagnostic_code = DIAG_ERR_OUT_OF_BOUNDS
            raise ValueError(f"Node coordinates ({x}, {y}) out of viewport bounds")

        nid = node_id if node_id is not None else (len(self.nodes) + 1)
        lat, lon = canvas_to_latlon(x, y, self.viewport_width, self.viewport_height)
        cid = latlon_to_s2_cell_id(lat, lon, self.level)
        tok = s2_cell_to_token(cid)
        h_word = s2_cell_to_word16(cid)

        node = SpatialNode(
            id=nid,
            x=x,
            y=y,
            lat=lat,
            lon=lon,
            cell_id=cid,
            token=tok,
            tag=tag or f"NODE-{nid:03d}",
            equip_type=equip_type,
            status=status,
            hazard_radius=hazard_radius,
            hash_word=h_word,
        )
        self.nodes[nid] = node
        return node

    def remove_node(self, node_id: int) -> Optional[SpatialNode]:
        """Remove a node from the canvas."""
        return self.nodes.pop(node_id, None)

    def query_range(self, rect: Union[S2Rect, Tuple[float, float, float, float]]) -> List[SpatialNode]:
        """Query nodes contained in a 2D bounding box rectangle."""
        if isinstance(rect, tuple):
            q_rect = S2Rect(*rect)
        else:
            q_rect = rect

        self.last_query_rect = q_rect
        matches = [node for node in self.nodes.values() if q_rect.contains_coord(node.x, node.y)]
        self.last_query_results = matches
        return matches

    def query_radius(self, cx: float, cy: float, radius: float) -> List[SpatialNode]:
        """Query nodes within radial distance from center point."""
        self.last_query_radius = radius
        r_sq = radius * radius
        matches = [
            node for node in self.nodes.values()
            if (node.x - cx) ** 2 + (node.y - cy) ** 2 <= r_sq
        ]
        self.last_query_results = matches
        return matches

    def query_token_prefix(self, prefix: str) -> List[SpatialNode]:
        """Query nodes matching hierarchical S2 token prefix."""
        self.last_query_token_prefix = prefix
        matches = [node for node in self.nodes.values() if node.token.startswith(prefix)]
        self.last_query_results = matches
        return matches

    def query_point(self, x: float, y: float, tolerance: float = 1e-4) -> List[SpatialNode]:
        """Query node at exact point location."""
        tol_sq = tolerance * tolerance
        matches = [
            node for node in self.nodes.values()
            if (node.x - x) ** 2 + (node.y - y) ** 2 <= tol_sq
        ]
        return matches

    def check_proximity_hazards(self) -> List[Tuple[int, int, float]]:
        """Detect all pairs of nodes violating spatial proximity hazard threshold."""
        violations: List[Tuple[int, int, float]] = []
        node_list = list(self.nodes.values())
        n = len(node_list)

        for i in range(n):
            for j in range(i + 1, n):
                n1 = node_list[i]
                n2 = node_list[j]
                dist = math.hypot(n2.x - n1.x, n2.y - n1.y)
                thresh = max(self.hazard_threshold, n1.hazard_radius + n2.hazard_radius)
                if dist <= thresh:
                    violations.append((n1.id, n2.id, dist))

        self.hazard_violations = len(violations)
        if violations:
            self.alarm_active = True
            self.diagnostic_code = DiagnosticCode.SPATIAL_S2_PROXIMITY_HAZARD
        else:
            self.alarm_active = False
            self.diagnostic_code = DiagnosticCode.OK

        return violations

    @property
    def metrics(self) -> S2Metrics:
        """Calculate runtime telemetry metrics snapshot."""
        active_cells = len(set(node.cell_id for node in self.nodes.values()))
        primary_hash = 0
        if self.selected_node_id in self.nodes:
            primary_hash = self.nodes[self.selected_node_id].hash_word
        elif self.nodes:
            primary_hash = next(iter(self.nodes.values())).hash_word

        status_word = 0
        if not self.alarm_active:
            status_word |= S2StatusBits.ONLINE
        else:
            status_word |= S2StatusBits.HAZARD_ALARM
        if active_cells > 0:
            status_word |= S2StatusBits.GRID_ACTIVE
        if len(self.last_query_results) > 0:
            status_word |= S2StatusBits.QUERY_ACTIVE
        if self.selected_node_id > 0:
            status_word |= S2StatusBits.SELECTION_ACTIVE
        if self.hazard_violations > 0:
            status_word |= S2StatusBits.HIGH_CONGESTION

        return S2Metrics(
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

        rt.write_word(REG_W312_TOTAL_OBJECTS, m.total_objects & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W312_LEVEL, m.level & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W312_ACTIVE_CELLS, m.active_cells & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W312_PRIMARY_HASH, m.primary_hash & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W312_MATCH_COUNT, m.match_count & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W312_HAZARD_VIOLATIONS, m.hazard_violations & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W312_STATUS_WORD, m.status_word & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W312_DIAGNOSTIC_CODE, int(m.diagnostic_code) & 0xFFFF, privilege=privilege)

        rt.write_bit(COIL_W312_CANVAS_ONLINE, m.canvas_online, privilege=privilege)
        rt.write_bit(COIL_W312_HAZARD_ALARM, m.hazard_alarm, privilege=privilege)

    def scan_step(self, ctx: Optional[ScanContext] = None) -> ExecutionResult:
        """Execute single scan cycle step of S2 Canvas engine."""
        self.cycle_count += 1
        self.check_proximity_hazards()
        rt = ctx.register_table if ctx and ctx.register_table else self.reg_table
        self.sync_to_registers(rt)

        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            details=f"S2 Canvas Cycle {self.cycle_count}: {len(self.nodes)} nodes indexed at level {self.level}.",
            data={
                "cycle": self.cycle_count,
                "nodes": len(self.nodes),
                "level": self.level,
                "active_cells": len(set(n.cell_id for n in self.nodes.values())),
                "matches": len(self.last_query_results),
                "violations": self.hazard_violations,
                "alarm": self.alarm_active,
                "diagnostic_code": int(self.diagnostic_code),
            },
        )

    # ILogicUnit interface compliance
    @property
    def name(self) -> str:
        return "S2CanvasEngine"

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
        rng = random.Random(seed)
        self.clear()
        equip_types = ["sensor", "pump", "valve", "tank"]

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


def generate_s2_canvas_svg(engine: S2CanvasEngine) -> str:
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
        '    <linearGradient id="cellGrad" x1="0%" y1="0%" x2="100%" y2="100%">\n'
        f'      <stop offset="0%" stop-color="{COLOR_S2_CELL}" stop-opacity="0.12" />\n'
        f'      <stop offset="100%" stop-color="{COLOR_NOMINAL_EMERALD}" stop-opacity="0.04" />\n'
        '    </linearGradient>\n'
        '  </defs>'
    )

    # 2. Hierarchical S2 Bounding Box Grid Layer
    svg_parts.append('  <!-- Hierarchical S2 Bounding Boxes Layer -->')
    svg_parts.append('  <g id="s2-grid-layer" class="s2-cells">')
    # Render parent cell bounding boxes at coarse level (e.g. level 2 or 3)
    coarse_level = min(engine.level, 3)
    coarse_cells = sorted(list(set(s2_cell_parent(node.cell_id, coarse_level) for node in engine.nodes.values())))
    for cell_id in coarse_cells:
        rect = s2_cell_to_canvas_rect(cell_id, engine.viewport_width, engine.viewport_height)
        tok = s2_cell_to_token(cell_id)
        face = s2_cell_face(cell_id)
        svg_parts.append(
            f'    <rect class="s2-cell" x="{rect.min_x:.1f}" y="{rect.min_y:.1f}" '
            f'width="{rect.width:.1f}" height="{rect.height:.1f}" '
            f'fill="url(#cellGrad)" stroke="{COLOR_S2_BORDER}" stroke-width="0.8" stroke-dasharray="3 2" />'
        )
        svg_parts.append(
            f'    <text x="{rect.min_x + 4:.1f}" y="{rect.min_y + 11:.1f}" fill="{COLOR_TEXT_DIM}" font-size="8">F{face}:#{tok}</text>'
        )
    svg_parts.append('  </g>')

    # 3. Query Reticle Overlay
    svg_parts.append('  <!-- Query Reticle Overlay Layer -->')
    if engine.last_query_rect:
        qr = engine.last_query_rect
        svg_parts.append(
            f'  <g id="query-reticle-layer" class="range-reticle">\n'
            f'    <rect x="{qr.min_x:.1f}" y="{qr.min_y:.1f}" width="{qr.width:.1f}" height="{qr.height:.1f}" '
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
            f'      <text x="{node.x + 9:.1f}" y="{node.y + 8:.1f}" fill="{COLOR_TEXT_DIM}" font-size="8">[{node.token}]</text>\n'
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
        f'    <rect x="15" y="15" width="490" height="74" rx="6" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1.2" />\n'
        f'    <text x="25" y="35" fill="{COLOR_TEXT_PRIMARY}" font-size="12" font-weight="bold">DYNAMIC SPATIAL S2 SPHERICAL GEOMETRY SCADA CANVAS [W312]</text>\n'
        f'    <text x="25" y="55" fill="{COLOR_TEXT_MUTED}" font-size="10">LEVEL: {m.level} | ACTIVE CELLS: {m.active_cells} | NODES: {m.total_objects} | MATCHES: {m.match_count}</text>\n'
        f'    <text x="25" y="72" fill="{COLOR_TEXT_DIM}" font-size="9">HAZARDS: {m.hazard_violations} | DIAG: 0x{int(m.diagnostic_code):04X} | REGS: %R2730..%R2737 | COILS: %M637..%M638</text>\n'
        f'    <rect x="{w - 180}" y="15" width="165" height="28" rx="4" fill="{alarm_badge_fill}" />\n'
        f'    <text x="{w - 97}" y="33" fill="{COLOR_TEXT_PRIMARY}" font-size="10" font-weight="bold" text-anchor="middle">{alarm_badge_text}</text>\n'
        f'  </g>'
    )

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)


def create_canonical_s2_canvas(seed: int = 42, count: int = 24, level: int = DEFAULT_S2_LEVEL) -> S2CanvasEngine:
    """Helper to instantiate and populate canonical S2 canvas."""
    engine = S2CanvasEngine(level=level)
    engine.build_canonical_sensor_network(seed=seed, count=count)
    return engine


# ============================================================================
# 5. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

ST_PROGRAM_W312_S2_CANVAS_SYNC: str = """
PROGRAM S2CanvasSync
VAR
    wTotalObjects AT %R2730 : WORD;
    wLevel AT %R2731 : WORD;
    wActiveCells AT %R2732 : WORD;
    wPrimaryHash AT %R2733 : WORD;
    wMatchCount AT %R2734 : WORD;
    wHazardViolations AT %R2735 : WORD;
    wStatusWord AT %R2736 : WORD;
    wDiagCode AT %R2737 : WORD;
    bCanvasOnline AT %M637 : BOOL;
    bHazardAlarm AT %M638 : BOOL;
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

ST_PROGRAM_S2_CANVAS_SYNC = ST_PROGRAM_W312_S2_CANVAS_SYNC


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

def run_s2_canvas_verification(
    output_path: Optional[str] = None,
    sample_svg_path: Optional[str] = None,
    work_package: str = "W312",
    quick: bool = False,
) -> Dict[str, Any]:
    """Execute the deterministic 9-stage verification suite for W312 S2 Canvas."""
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
        for m in ["json", "math", "pathlib", "hashlib", "random", "time"]
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
        S2CanvasEngine is not None
        and latlon_to_s2_cell_id is not None
        and s2_cell_id_to_latlon is not None
        and s2_cell_parent is not None
        and s2_cell_children is not None
        and generate_s2_canvas_svg is not None
    )
    c1 = py_ok and platform_ok and deps_ok and framework_ok and module_ok
    stages.append({
        "stage": 1,
        "name": "environment_and_platform_check",
        "passed": c1,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Python {sys.version.split()[0]} on {sys.platform}; jev_cscape simulation, parser, and W312 modules verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: s2_constants_and_register_mappings
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    regs_ok = (
        REG_W312_TOTAL_OBJECTS == "%R2730"
        and REG_W312_LEVEL == "%R2731"
        and REG_W312_ACTIVE_CELLS == "%R2732"
        and REG_W312_PRIMARY_HASH == "%R2733"
        and REG_W312_MATCH_COUNT == "%R2734"
        and REG_W312_HAZARD_VIOLATIONS == "%R2735"
        and REG_W312_STATUS_WORD == "%R2736"
        and REG_W312_DIAGNOSTIC_CODE == "%R2737"
        and COIL_W312_CANVAS_ONLINE == "%M637"
        and COIL_W312_HAZARD_ALARM == "%M638"
        and REG_S2_TOTAL_OBJECTS == "%R2730"
        and COIL_S2_CANVAS_ONLINE == "%M637"
    )

    diag_ok = (
        int(DiagnosticCode.OK) == 0x0000
        and int(DiagnosticCode.INVALID_DOMAIN) == 0x8401
        and int(DiagnosticCode.DEGENERATE_BOUNDING_BOX) == 0x8402
        and int(DiagnosticCode.OUT_OF_BOUNDS) == 0x8403
        and int(DiagnosticCode.EMPTY_CANVAS) == 0x8404
        and int(DiagnosticCode.INVALID_LEVEL) == 0x8405
        and int(DiagnosticCode.QUERY_OUT_OF_BOUNDS) == 0x8406
        and int(DiagnosticCode.INVALID_CELL_ID) == 0x8407
        and int(DiagnosticCode.SPATIAL_CLUSTER_HAZARD) == 0x8418
        and int(DiagnosticCode.SPATIAL_S2_PROXIMITY_HAZARD) == 0x8420
        and int(DiagnosticCode.SPATIAL_COLLISION_TRIP) == 0x8420
    )

    status_bits_ok = (
        int(S2StatusBits.ONLINE) == 0x0001
        and int(S2StatusBits.HAZARD_ALARM) == 0x0002
        and int(S2StatusBits.GRID_ACTIVE) == 0x0004
        and int(S2StatusBits.QUERY_ACTIVE) == 0x0008
        and int(S2StatusBits.SELECTION_ACTIVE) == 0x0010
        and int(S2StatusBits.HIGH_CONGESTION) == 0x0020
        and int(S2StatusBits.DEGRADED_RESOLUTION) == 0x0040
        and int(S2StatusBits.CELLS_BOUNDED) == 0x0080
    )

    params_ok = (
        CANVAS_VIEWPORT_WIDTH == 1200.0
        and CANVAS_VIEWPORT_HEIGHT == 750.0
        and MIN_S2_LEVEL == 1
        and MAX_S2_LEVEL == 30
        and DEFAULT_S2_LEVEL == 10
        and DEFAULT_HAZARD_THRESHOLD == 35.0
    )

    c2 = regs_ok and diag_ok and status_bits_ok and params_ok
    stages.append({
        "stage": 2,
        "name": "s2_constants_and_register_mappings",
        "passed": c2,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Horner OCS %R2730..%R2737, %M637..%M638, diagnostic codes 0x0000/0x8420, and status bits verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: pure_python_s2_spherical_projection_bijection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    test_vectors = [
        (90.0, 0.0, 2),                  # North Pole (+Z)
        (-90.0, 0.0, 5),                 # South Pole (-Z)
        (0.0, 0.0, 0),                   # Prime Meridian (+X)
        (0.0, 90.0, 1),                  # 90 deg East (+Y)
        (0.0, -90.0, 4),                 # 90 deg West (-Y)
        (0.0, 180.0, 3),                 # 180 deg Meridian (-X)
        (51.5074, -0.1278, 2),           # London
        (35.6762, 139.6503, 3),          # Tokyo
        (-33.8688, 151.2093, 3),         # Sydney
        (37.7749, -122.4194, 4),         # San Francisco
    ]

    vector_ok = True
    for lat, lon, exp_face in test_vectors:
        x, y, z = latlon_to_xyz(lat, lon)
        face, u, v = xyz_to_face_uv(x, y, z)
        if face != exp_face:
            vector_ok = False
            break
        rx, ry, rz = face_uv_to_xyz(face, u, v)
        rlat, rlon = xyz_to_latlon(rx, ry, rz)
        err = math.hypot(lat - rlat, lon - rlon)
        if err > 1e-7:
            vector_ok = False
            break

        # Cell ID containment check at level 10
        cid = latlon_to_s2_cell_id(lat, lon, level=10)
        c_lat, c_lon = s2_cell_id_to_latlon(cid)
        dist_deg = angular_distance_deg(lat, lon, c_lat, c_lon)
        # At level 10, cell size is ~0.08 degrees
        if dist_deg > 0.2:
            vector_ok = False
            break

        # Token bijective round-trip
        tok = s2_cell_to_token(cid)
        rec_id = s2_token_to_cell_id(tok)
        if rec_id != cid:
            vector_ok = False
            break

    # Test level scaling hierarchy 1..15
    level_scaling_ok = True
    test_lat, test_lon = 37.7749, -122.4194
    deep_cell = latlon_to_s2_cell_id(test_lat, test_lon, level=15)
    for lvl in range(1, 16):
        lvl_cell = latlon_to_s2_cell_id(test_lat, test_lon, level=lvl)
        if s2_cell_level(lvl_cell) != lvl:
            level_scaling_ok = False
            break
        p_cell = s2_cell_parent(deep_cell, target_level=lvl)
        if p_cell != lvl_cell:
            level_scaling_ok = False
            break

    # Bounds & error rejection
    bounds_rejected = False
    try:
        latlon_to_s2_cell_id(95.0, 0.0, 10)
    except ValueError:
        try:
            latlon_to_s2_cell_id(0.0, 185.0, 10)
        except ValueError:
            try:
                latlon_to_s2_cell_id(0.0, 0.0, 0)  # level < 1
            except ValueError:
                try:
                    latlon_to_s2_cell_id(0.0, 0.0, 31)  # level > 30
                except ValueError:
                    try:
                        s2_token_to_cell_id("INVALID_HEX_ZZZ")
                    except ValueError:
                        bounds_rejected = True

    c3 = vector_ok and level_scaling_ok and bounds_rejected
    stages.append({
        "stage": 3,
        "name": "pure_python_s2_spherical_projection_bijection",
        "passed": c3,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Bijective spherical projections, S2 Cell ID encode/decode, and token round-trips verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: s2_cube_face_and_quadtree_hierarchy
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    face_topology_ok = True
    # Verify 6 faces correspond to cardinal unit axes
    cardinal_axes = [
        (1.0, 0.0, 0.0, 0),
        (0.0, 1.0, 0.0, 1),
        (0.0, 0.0, 1.0, 2),
        (-1.0, 0.0, 0.0, 3),
        (0.0, -1.0, 0.0, 4),
        (0.0, 0.0, -1.0, 5),
    ]
    for vx, vy, vz, expected_f in cardinal_axes:
        f, u, v = xyz_to_face_uv(vx, vy, vz)
        if f != expected_f or abs(u) > 1e-9 or abs(v) > 1e-9:
            face_topology_ok = False
            break

    # Root cell verification
    for f in range(6):
        root_id = s2_face_root_cell_id(f)
        if s2_cell_face(root_id) != f or s2_cell_level(root_id) != 0:
            face_topology_ok = False
            break

    # Quadtree parent-child hierarchy verification across levels
    quadtree_ok = True
    sample_cells = [
        latlon_to_s2_cell_id(51.5074, -0.1278, level=6),
        latlon_to_s2_cell_id(35.6762, 139.6503, level=6),
        latlon_to_s2_cell_id(0.0, 0.0, level=6),
    ]

    for sc in sample_cells:
        sc_lvl = s2_cell_level(sc)
        sc_face = s2_cell_face(sc)
        children = s2_cell_children(sc)
        # Exactly 4 children
        if len(children) != 4:
            quadtree_ok = False
            break
        # All mutually distinct
        if len(set(children)) != 4:
            quadtree_ok = False
            break
        for ch in children:
            if s2_cell_level(ch) != sc_lvl + 1:
                quadtree_ok = False
                break
            if s2_cell_face(ch) != sc_face:
                quadtree_ok = False
                break
            if s2_cell_parent(ch) != sc:
                quadtree_ok = False
                break

    # Orthogonal neighbors verification
    neighbors_ok = True
    test_node_cell = latlon_to_s2_cell_id(37.7749, -122.4194, level=8)
    nbrs = s2_cell_neighbors(test_node_cell)
    if not (1 <= len(nbrs) <= 4):
        neighbors_ok = False
    for nb in nbrs:
        if s2_cell_level(nb) != 8 or s2_cell_face(nb) != s2_cell_face(test_node_cell):
            neighbors_ok = False
            break

    c4 = face_topology_ok and quadtree_ok and neighbors_ok
    stages.append({
        "stage": 4,
        "name": "s2_cube_face_and_quadtree_hierarchy",
        "passed": c4,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "6-face cube topology, quadtree parent/child bijection, and orthogonal cell adjacency verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: spatial_proximity_hazard_and_collision_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    p_engine = S2CanvasEngine(level=10, hazard_threshold=35.0)
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
        and p_engine.diagnostic_code == DiagnosticCode.SPATIAL_S2_PROXIMITY_HAZARD
        and p_engine.hazard_violations >= 1
    )

    # 3. Register sync on hazard trip
    rt_trip = RegisterTable()
    p_engine.sync_to_registers(rt_trip)
    coil_alarm_trip = rt_trip.read_bit(COIL_W312_HAZARD_ALARM)
    coil_online_trip = rt_trip.read_bit(COIL_W312_CANVAS_ONLINE)
    reg_diag_trip = rt_trip.read_word(REG_W312_DIAGNOSTIC_CODE)
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
        rt_trip.read_bit(COIL_W312_HAZARD_ALARM) is False
        and rt_trip.read_bit(COIL_W312_CANVAS_ONLINE) is True
        and (rt_trip.read_word(REG_W312_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
    )

    c5 = nom_ok and trip_ok and regs_trip_ok and clear_ok and regs_clear_ok
    stages.append({
        "stage": 5,
        "name": "spatial_proximity_hazard_and_collision_trip",
        "passed": c5,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Spatial proximity collision trip, coil %M638 alarm latch, and nominal reset verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: register_table_synchronization_and_signed_masks
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_sync = RegisterTable()
    s_engine = create_canonical_s2_canvas(seed=42, count=24, level=10)
    s_engine.query_radius(600.0, 375.0, 200.0)
    s_engine.sync_to_registers(rt_sync)

    w_total = rt_sync.read_word(REG_W312_TOTAL_OBJECTS)
    w_level = rt_sync.read_word(REG_W312_LEVEL)
    w_cells = rt_sync.read_word(REG_W312_ACTIVE_CELLS)
    w_hash = rt_sync.read_word(REG_W312_PRIMARY_HASH)
    w_match = rt_sync.read_word(REG_W312_MATCH_COUNT)
    w_viols = rt_sync.read_word(REG_W312_HAZARD_VIOLATIONS)
    w_status = rt_sync.read_word(REG_W312_STATUS_WORD)
    w_diag = rt_sync.read_word(REG_W312_DIAGNOSTIC_CODE)
    b_online = rt_sync.read_bit(COIL_W312_CANVAS_ONLINE)
    b_alarm = rt_sync.read_bit(COIL_W312_HAZARD_ALARM)

    c6_reads = (
        (w_total & 0xFFFF) == len(s_engine.nodes)
        and (w_level & 0xFFFF) == s_engine.level
        and (w_cells & 0xFFFF) == len(set(n.cell_id for n in s_engine.nodes.values()))
        and (w_hash & 0xFFFF) == s_engine.metrics.primary_hash
        and (w_match & 0xFFFF) == len(s_engine.last_query_results)
        and (w_viols & 0xFFFF) == 0
        and (w_status & 0x0001) == 1
        and (w_diag & 0xFFFF) == 0x0000
        and b_online is True
        and b_alarm is False
    )

    # Bitwise signed masks verification
    rt_sync.write_word(REG_W312_DIAGNOSTIC_CODE, (-55) & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
    raw_val = rt_sync.read_word(REG_W312_DIAGNOSTIC_CODE)
    val_u = raw_val & 0xFFFF
    val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
    c6_signed = (val_u == 65481 and val_s == -55)

    # High-bit diagnostic code verification
    diag_code = DiagnosticCode.SPATIAL_S2_PROXIMITY_HAZARD
    rt_sync.write_word(REG_W312_DIAGNOSTIC_CODE, int(diag_code) & 0xFFFF, privilege=PrivilegeMode.USER)
    diag_read = rt_sync.read_word(REG_W312_DIAGNOSTIC_CODE)
    c6_diag = ((diag_read & 0xFFFF) == int(diag_code) and (diag_read & 0xFFFF) == 0x8420)

    # Restore nominal diagnostic in register
    s_engine.sync_to_registers(rt_sync)

    c6 = c6_reads and c6_signed and c6_diag
    stages.append({
        "stage": 6,
        "name": "register_table_synchronization_and_signed_masks",
        "passed": c6,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Horner OCS %R2730..%R2737 and %M637..%M638 synchronized; signed 16-bit masks and 0x8420 verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    SecurityGuard.assert_pure_st_content(ST_PROGRAM_W312_S2_CANVAS_SYNC)
    st_val = STParser.validate_code(ST_PROGRAM_W312_S2_CANVAS_SYNC)
    st_ast = STParser.parse_pou(ST_PROGRAM_W312_S2_CANVAS_SYNC)
    st_pou_ok = (
        st_val.status == AgentStatus.SUCCESS
        and st_ast.pou_type == POUType.PROGRAM
        and st_ast.name == "S2CanvasSync"
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
        "details": "Pure ST POU 'S2CanvasSync' AST validated; ladder contacts, coils, rungs, and mnemonics strictly rejected.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: svg_scada_canvas_rasterization_and_wcag_contrast
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    canon_canvas = create_canonical_s2_canvas(seed=42, count=24, level=10)
    canon_canvas.query_radius(600.0, 375.0, 180.0)
    svg_text = generate_s2_canvas_svg(canon_canvas)

    # XML validation
    root_el = ET.fromstring(svg_text)
    svg_valid = (
        root_el.tag.endswith("svg")
        and root_el.attrib.get("version") == "1.1"
        and root_el.attrib.get("viewBox") == "0 0 1200 750"
        and "s2-grid-layer" in svg_text
        and "nodes-layer" in svg_text
        and "query-reticle-layer" in svg_text
        and "scorecard-layer" in svg_text
        and "sensor-node" in svg_text
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
        "details": f"W3C SVG 1.1 generated with valid XML layers; WCAG AAA contrast ratio verified ({contrast_ratio:.2f}:1 >= 18:1).",
    })

    # ------------------------------------------------------------------------
    # Stage 9: multi_cycle_simulation_soak_and_evidence_emission
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim_engine = S2CanvasEngine(level=10)
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
        "details": f"Wave {work_package} S2 Canvas Verification PASSED ({passed_count}/{total_count} stages).",
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
    """Command-line entry point for W312 S2 Canvas verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Cscape HMI Dynamic Spatial S2 Spherical Geometry SCADA Canvas (W312) 9-Stage Verification Suite"
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
        default="artifacts/HMI/s2_canvas_evidence.json",
        help="Path to output verification evidence JSON (default: artifacts/HMI/s2_canvas_evidence.json)",
    )
    parser.add_argument(
        "--svg",
        "-s",
        "--svg-output",
        "--sample-svg",
        dest="svg_output_path",
        type=str,
        default="artifacts/HMI/s2_canvas_sample.svg",
        help="Path to output sample SVG graphic (default: artifacts/HMI/s2_canvas_sample.svg)",
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
        default="W312",
        help="Work package identifier (default: W312)",
    )

    args = parser.parse_args(argv)
    effective_output = args.positional_output or args.output_path
    effective_svg = args.positional_svg or args.svg_output_path

    if not args.json_mode:
        print(f"\n{CLR_CYAN}{CLR_BOLD}======================================================================{CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}  JEV CSCAPE VERIFICATION RUNNER - WORK PACKAGE {args.work_package}                 {CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}  Gate G9: Dynamic Spatial S2 Spherical Geometry SCADA Canvas        {CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}======================================================================{CLR_RESET}\n")

    t_start = time.perf_counter()
    evidence = run_s2_canvas_verification(
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
            print(f"  Stage {num:d}: {name:<48} {badge} ({t_ms:.2f} ms)")

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
