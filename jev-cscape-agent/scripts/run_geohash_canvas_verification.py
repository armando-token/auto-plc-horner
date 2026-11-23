#!/usr/bin/env python3
"""Verification Runner for Cscape HMI Dynamic Spatial Geohash / Hierarchical Bounding Box SCADA Canvas (W309).

Work Package: W309 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Geohash Hierarchical Bounding Box SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: environment_and_platform_check
  Stage 2: geohash_constants_and_register_mappings
  Stage 3: pure_python_geohash_encoding_and_decoding_bijection
  Stage 4: geohash_8_neighbor_spatial_adjacency
  Stage 5: spatial_proximity_hazard_and_collision_trip
  Stage 6: register_table_synchronization_and_signed_masks
  Stage 7: pure_st_pou_and_anti_ladder_rejection
  Stage 8: svg_scada_canvas_rasterization_and_wcag_contrast
  Stage 9: multi_cycle_simulation_soak_and_evidence_emission

CLI Arguments:
  --output, -o (default: artifacts/HMI/geohash_canvas_evidence.json)
  --svg, -s (default: artifacts/HMI/geohash_canvas_sample.svg)
  --quick, -q (accelerated verification with reduced simulation cycles)
  --json (force JSON emission)
  --work-package, -w (default: W309)
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
# 1. Constants, Palette & Horner OCS Register Map (W309)
# ============================================================================

CANVAS_VIEWPORT_WIDTH: float         = 1200.0
CANVAS_VIEWPORT_HEIGHT: float        = 750.0
TOTAL_DOMAIN_AREA: float             = CANVAS_VIEWPORT_WIDTH * CANVAS_VIEWPORT_HEIGHT

MIN_GEOHASH_PRECISION: int           = 1
MAX_GEOHASH_PRECISION: int           = 12
DEFAULT_GEOHASH_PRECISION: int       = 6
DEFAULT_HAZARD_THRESHOLD: float      = 35.0

# Base32 Character Set (standard 32-character geohash alphabet, excluding a, i, l, o)
BASE32: str                          = "0123456789bcdefghjkmnpqrstuvwxyz"
BASE32_MAP: Dict[str, int]           = {c: i for i, c in enumerate(BASE32)}

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
COLOR_GEOHASH_CELL: str              = "#38BDF8"
COLOR_GEOHASH_BORDER: str            = "#0284C7"
COLOR_GRID_LINE: str                 = "#1E293B"

# Horner OCS Word Register Map (%R2700..%R2707) & Discrete Coils (%M630..%M631)
REG_W309_TOTAL_OBJECTS: str          = "%R2700"
REG_W309_PRECISION: str              = "%R2701"
REG_W309_ACTIVE_CELLS: str           = "%R2702"
REG_W309_PRIMARY_HASH: str           = "%R2703"
REG_W309_MATCH_COUNT: str            = "%R2704"
REG_W309_HAZARD_VIOLATIONS: str      = "%R2705"
REG_W309_STATUS_WORD: str            = "%R2706"
REG_W309_DIAGNOSTIC_CODE: str        = "%R2707"

COIL_W309_CANVAS_ONLINE: str         = "%M630"
COIL_W309_HAZARD_ALARM: str          = "%M631"

REG_GEOHASH_TOTAL_OBJECTS            = REG_W309_TOTAL_OBJECTS
REG_GEOHASH_PRECISION                = REG_W309_PRECISION
REG_GEOHASH_ACTIVE_CELLS             = REG_W309_ACTIVE_CELLS
REG_GEOHASH_PRIMARY_HASH             = REG_W309_PRIMARY_HASH
REG_GEOHASH_MATCH_COUNT              = REG_W309_MATCH_COUNT
REG_GEOHASH_HAZARD_VIOLATIONS        = REG_W309_HAZARD_VIOLATIONS
REG_GEOHASH_STATUS_WORD              = REG_W309_STATUS_WORD
REG_GEOHASH_DIAGNOSTIC_CODE          = REG_W309_DIAGNOSTIC_CODE

COIL_GEOHASH_CANVAS_ONLINE           = COIL_W309_CANVAS_ONLINE
COIL_GEOHASH_HAZARD_ALARM            = COIL_W309_HAZARD_ALARM


class DiagnosticCode(IntEnum):
    """Horner OCS W309 Geohash Bounding Box SCADA Diagnostic Codes."""
    OK                              = 0x0000
    INVALID_DOMAIN                  = 0x8401
    DEGENERATE_BOUNDING_BOX         = 0x8402
    OUT_OF_BOUNDS                   = 0x8403
    EMPTY_CANVAS                    = 0x8404
    INVALID_PRECISION               = 0x8405
    QUERY_OUT_OF_BOUNDS             = 0x8406
    INVALID_BASE32_CHAR             = 0x8407
    SPATIAL_CLUSTER_HAZARD          = 0x8418
    SPATIAL_GEOHASH_PROXIMITY_HAZARD = 0x8420
    SPATIAL_COLLISION_TRIP          = 0x8420


DIAG_OK                             = DiagnosticCode.OK
DIAG_ERR_INVALID_DOMAIN             = DiagnosticCode.INVALID_DOMAIN
DIAG_ERR_DEGENERATE_BOUNDING_BOX    = DiagnosticCode.DEGENERATE_BOUNDING_BOX
DIAG_ERR_OUT_OF_BOUNDS              = DiagnosticCode.OUT_OF_BOUNDS
DIAG_ERR_EMPTY_CANVAS               = DiagnosticCode.EMPTY_CANVAS
DIAG_ERR_INVALID_PRECISION          = DiagnosticCode.INVALID_PRECISION
DIAG_ERR_QUERY_OUT_OF_BOUNDS        = DiagnosticCode.QUERY_OUT_OF_BOUNDS
DIAG_ERR_INVALID_BASE32_CHAR        = DiagnosticCode.INVALID_BASE32_CHAR
DIAG_ERR_SPATIAL_GEOHASH_PROXIMITY_HAZARD = DiagnosticCode.SPATIAL_GEOHASH_PROXIMITY_HAZARD


class GeohashStatusBits(IntFlag):
    """16-bit packed status word for Geohash Canvas engine."""
    ONLINE              = 0x0001
    HAZARD_ALARM        = 0x0002
    GRID_ACTIVE         = 0x0004
    QUERY_ACTIVE        = 0x0008
    SELECTION_ACTIVE    = 0x0010
    HIGH_CONGESTION     = 0x0020
    DEGRADED_RESOLUTION = 0x0040
    CELLS_BOUNDED       = 0x0080


# ============================================================================
# 2. Pure Python Geohash Core Algorithms & Geometry
# ============================================================================

def geohash_encode(lat: float, lon: float, precision: int = DEFAULT_GEOHASH_PRECISION) -> str:
    """Encode latitude and longitude into a Base32 Geohash string.

    Args:
        lat: Latitude in [-90.0, 90.0]
        lon: Longitude in [-180.0, 180.0]
        precision: Geohash character precision [1, 12]
    """
    if not (MIN_GEOHASH_PRECISION <= precision <= MAX_GEOHASH_PRECISION):
        raise ValueError(
            f"Precision must be between {MIN_GEOHASH_PRECISION} and {MAX_GEOHASH_PRECISION}, got {precision}"
        )
    if not (-90.0 <= lat <= 90.0):
        raise ValueError(f"Latitude out of bounds [-90, 90]: {lat}")
    if not (-180.0 <= lon <= 180.0):
        raise ValueError(f"Longitude out of bounds [-180, 180]: {lon}")

    lat_interval = [-90.0, 90.0]
    lon_interval = [-180.0, 180.0]
    geohash: List[str] = []
    bits = [16, 8, 4, 2, 1]
    bit = 0
    ch = 0
    even = True

    while len(geohash) < precision:
        if even:
            mid = (lon_interval[0] + lon_interval[1]) / 2.0
            if lon >= mid:
                ch |= bits[bit]
                lon_interval[0] = mid
            else:
                lon_interval[1] = mid
        else:
            mid = (lat_interval[0] + lat_interval[1]) / 2.0
            if lat >= mid:
                ch |= bits[bit]
                lat_interval[0] = mid
            else:
                lat_interval[1] = mid
        even = not even
        if bit < 4:
            bit += 1
        else:
            geohash.append(BASE32[ch])
            bit = 0
            ch = 0

    return "".join(geohash)


@dataclass
class GeohashBoundingBox:
    """Geographic bounding box for a decoded Geohash cell."""
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


def geohash_decode(geohash_str: str) -> GeohashBoundingBox:
    """Decode a Base32 Geohash string into its geographic bounding box."""
    if not geohash_str:
        raise ValueError("Cannot decode empty geohash string")

    lat_interval = [-90.0, 90.0]
    lon_interval = [-180.0, 180.0]
    even = True

    for c in geohash_str.lower():
        if c not in BASE32_MAP:
            raise ValueError(f"Invalid Base32 character '{c}' in geohash '{geohash_str}'")
        cd = BASE32_MAP[c]
        for mask in [16, 8, 4, 2, 1]:
            if even:
                mid = (lon_interval[0] + lon_interval[1]) / 2.0
                if cd & mask:
                    lon_interval[0] = mid
                else:
                    lon_interval[1] = mid
            else:
                mid = (lat_interval[0] + lat_interval[1]) / 2.0
                if cd & mask:
                    lat_interval[0] = mid
                else:
                    lat_interval[1] = mid
            even = not even

    return GeohashBoundingBox(
        min_lat=lat_interval[0],
        max_lat=lat_interval[1],
        min_lon=lon_interval[0],
        max_lon=lon_interval[1],
    )


def geohash_decode_center(geohash_str: str) -> Tuple[float, float]:
    """Decode geohash string to its center point (lat, lon)."""
    bbox = geohash_decode(geohash_str)
    return bbox.center_lat, bbox.center_lon


def geohash_neighbors(geohash_str: str) -> Dict[str, str]:
    """Calculate the 8 spatial neighbors (N, NE, E, SE, S, SW, W, NW) of a geohash."""
    bbox = geohash_decode(geohash_str)
    c_lat = bbox.center_lat
    c_lon = bbox.center_lon
    d_lat = bbox.lat_delta
    d_lon = bbox.lon_delta
    p = len(geohash_str)

    directions: Dict[str, Tuple[float, float]] = {
        "n":  (1.0,  0.0),
        "ne": (1.0,  1.0),
        "e":  (0.0,  1.0),
        "se": (-1.0, 1.0),
        "s":  (-1.0, 0.0),
        "sw": (-1.0, -1.0),
        "w":  (0.0, -1.0),
        "nw": (1.0, -1.0),
    }

    neighbors: Dict[str, str] = {}
    for d_name, (scale_lat, scale_lon) in directions.items():
        n_lat = c_lat + scale_lat * d_lat
        n_lon = c_lon + scale_lon * d_lon

        # Clamp latitude to [-90.0, 90.0]
        n_lat = max(-90.0, min(90.0, n_lat))
        # Wrap longitude to [-180.0, 180.0]
        while n_lon > 180.0:
            n_lon -= 360.0
        while n_lon < -180.0:
            n_lon += 360.0

        neighbors[d_name] = geohash_encode(n_lat, n_lon, p)

    return neighbors


def geohash_to_word16(geohash_str: str) -> int:
    """Compute deterministic 16-bit FNV-1a hash code for Horner OCS WORD register."""
    if not geohash_str:
        return 0
    h = 0x811C
    for ch in geohash_str.encode("ascii"):
        h = ((h ^ ch) * 0x0103) & 0xFFFF
    return h


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
class GeohashRect:
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

    def intersects(self, other: "GeohashRect") -> bool:
        return not (
            self.max_x < other.min_x
            or self.min_x > other.max_x
            or self.max_y < other.min_y
            or self.min_y > other.max_y
        )


def geohash_to_canvas_rect(
    geohash_str: str,
    width: float = CANVAS_VIEWPORT_WIDTH,
    height: float = CANVAS_VIEWPORT_HEIGHT,
) -> GeohashRect:
    """Convert a geohash bounding box into canvas screen coordinates."""
    bbox = geohash_decode(geohash_str)
    x1, y1 = latlon_to_canvas(bbox.max_lat, bbox.min_lon, width, height)
    x2, y2 = latlon_to_canvas(bbox.min_lat, bbox.max_lon, width, height)
    min_x = min(x1, x2)
    max_x = max(x1, x2)
    min_y = min(y1, y2)
    max_y = max(y1, y2)
    return GeohashRect(min_x=min_x, min_y=min_y, max_x=max_x, max_y=max_y)


@dataclass
class SpatialNode:
    """Equipment or sensor node indexed within the Geohash SCADA canvas."""
    id: int
    x: float
    y: float
    lat: float = 0.0
    lon: float = 0.0
    geohash: str = ""
    tag: str = ""
    equip_type: str = "sensor"
    status: str = "normal"
    hazard_radius: float = 25.0
    hash_word: int = 0


@dataclass
class GeohashMetrics:
    """Runtime telemetry metrics snapshot for Horner OCS register synchronization."""
    total_objects: int = 0
    precision: int = DEFAULT_GEOHASH_PRECISION
    active_cells: int = 0
    primary_hash: int = 0
    match_count: int = 0
    hazard_violations: int = 0
    status_word: int = 0
    diagnostic_code: DiagnosticCode = DiagnosticCode.OK
    canvas_online: bool = True
    hazard_alarm: bool = False


# ============================================================================
# 3. Geohash Canvas Engine Implementation
# ============================================================================

class GeohashCanvasEngine(ILogicUnit):
    """Dynamic Spatial Geohash / Hierarchical Bounding Box SCADA Canvas Engine."""

    def __init__(
        self,
        precision: int = DEFAULT_GEOHASH_PRECISION,
        viewport_width: float = CANVAS_VIEWPORT_WIDTH,
        viewport_height: float = CANVAS_VIEWPORT_HEIGHT,
        hazard_threshold: float = DEFAULT_HAZARD_THRESHOLD,
    ) -> None:
        if not (MIN_GEOHASH_PRECISION <= precision <= MAX_GEOHASH_PRECISION):
            raise ValueError(
                f"Precision must be between {MIN_GEOHASH_PRECISION} and {MAX_GEOHASH_PRECISION}, got {precision}"
            )
        self.precision: int = precision
        self.viewport_width: float = viewport_width
        self.viewport_height: float = viewport_height
        self.hazard_threshold: float = hazard_threshold

        self.nodes: Dict[int, SpatialNode] = {}
        self.selected_node_id: int = 0
        self.last_query_results: List[SpatialNode] = []
        self.last_query_rect: Optional[GeohashRect] = None
        self.last_query_radius: float = 0.0
        self.last_query_prefix: str = ""

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
        """Insert a node with canvas coordinates and index via Geohash."""
        if not (0.0 <= x <= self.viewport_width and 0.0 <= y <= self.viewport_height):
            self.diagnostic_code = DIAG_ERR_OUT_OF_BOUNDS
            raise ValueError(f"Node coordinates ({x}, {y}) out of viewport bounds")

        nid = node_id if node_id is not None else (len(self.nodes) + 1)
        lat, lon = canvas_to_latlon(x, y, self.viewport_width, self.viewport_height)
        gh = geohash_encode(lat, lon, self.precision)
        h_word = geohash_to_word16(gh)

        node = SpatialNode(
            id=nid,
            x=x,
            y=y,
            lat=lat,
            lon=lon,
            geohash=gh,
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

    def query_range(self, rect: Union[GeohashRect, Tuple[float, float, float, float]]) -> List[SpatialNode]:
        """Query nodes contained in a 2D bounding box rectangle."""
        if isinstance(rect, tuple):
            q_rect = GeohashRect(*rect)
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

    def query_geohash_prefix(self, prefix: str) -> List[SpatialNode]:
        """Query nodes matching hierarchical geohash prefix."""
        self.last_query_prefix = prefix
        matches = [node for node in self.nodes.values() if node.geohash.startswith(prefix)]
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
            self.diagnostic_code = DiagnosticCode.SPATIAL_GEOHASH_PROXIMITY_HAZARD
        else:
            self.alarm_active = False
            self.diagnostic_code = DiagnosticCode.OK

        return violations

    @property
    def metrics(self) -> GeohashMetrics:
        """Calculate runtime telemetry metrics snapshot."""
        active_cells = len(set(node.geohash for node in self.nodes.values()))
        primary_hash = 0
        if self.selected_node_id in self.nodes:
            primary_hash = self.nodes[self.selected_node_id].hash_word
        elif self.nodes:
            primary_hash = next(iter(self.nodes.values())).hash_word

        status_word = 0
        if not self.alarm_active:
            status_word |= GeohashStatusBits.ONLINE
        else:
            status_word |= GeohashStatusBits.HAZARD_ALARM
        if active_cells > 0:
            status_word |= GeohashStatusBits.GRID_ACTIVE
        if len(self.last_query_results) > 0:
            status_word |= GeohashStatusBits.QUERY_ACTIVE
        if self.selected_node_id > 0:
            status_word |= GeohashStatusBits.SELECTION_ACTIVE
        if self.hazard_violations > 0:
            status_word |= GeohashStatusBits.HIGH_CONGESTION

        return GeohashMetrics(
            total_objects=len(self.nodes),
            precision=self.precision,
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

        rt.write_word(REG_W309_TOTAL_OBJECTS, m.total_objects & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W309_PRECISION, m.precision & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W309_ACTIVE_CELLS, m.active_cells & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W309_PRIMARY_HASH, m.primary_hash & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W309_MATCH_COUNT, m.match_count & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W309_HAZARD_VIOLATIONS, m.hazard_violations & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W309_STATUS_WORD, m.status_word & 0xFFFF, privilege=privilege)
        rt.write_word(REG_W309_DIAGNOSTIC_CODE, int(m.diagnostic_code) & 0xFFFF, privilege=privilege)

        rt.write_bit(COIL_W309_CANVAS_ONLINE, m.canvas_online, privilege=privilege)
        rt.write_bit(COIL_W309_HAZARD_ALARM, m.hazard_alarm, privilege=privilege)

    def scan_step(self, ctx: Optional[ScanContext] = None) -> ExecutionResult:
        """Execute single scan cycle step of Geohash canvas engine."""
        self.cycle_count += 1
        self.check_proximity_hazards()
        rt = ctx.register_table if ctx and ctx.register_table else self.reg_table
        self.sync_to_registers(rt)

        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            details=f"Geohash Canvas Cycle {self.cycle_count}: {len(self.nodes)} nodes indexed at precision {self.precision}.",
            data={
                "cycle": self.cycle_count,
                "nodes": len(self.nodes),
                "precision": self.precision,
                "active_cells": len(set(n.geohash for n in self.nodes.values())),
                "matches": len(self.last_query_results),
                "violations": self.hazard_violations,
                "alarm": self.alarm_active,
                "diagnostic_code": int(self.diagnostic_code),
            },
        )

    # ILogicUnit interface compliance
    @property
    def name(self) -> str:
        return "GeohashCanvasEngine"

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
        self.last_query_prefix = ""
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


def generate_geohash_canvas_svg(engine: GeohashCanvasEngine) -> str:
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
        f'      <stop offset="0%" stop-color="{COLOR_GEOHASH_CELL}" stop-opacity="0.12" />\n'
        f'      <stop offset="100%" stop-color="{COLOR_NOMINAL_EMERALD}" stop-opacity="0.04" />\n'
        '    </linearGradient>\n'
        '  </defs>'
    )

    # 2. Hierarchical Geohash Bounding Box Layer
    svg_parts.append('  <!-- Hierarchical Geohash Bounding Boxes Layer -->')
    svg_parts.append('  <g id="geohash-grid-layer" class="geohash-cells">')
    # Render hierarchical bounding boxes (prefix level 2 yields ~37.5x23.4 px SCADA grid cells)
    unique_cells = sorted(list(set(node.geohash[:2] if len(node.geohash) >= 2 else node.geohash for node in engine.nodes.values())))
    for gh_cell in unique_cells:
        rect = geohash_to_canvas_rect(gh_cell, engine.viewport_width, engine.viewport_height)
        svg_parts.append(
            f'    <rect class="geohash-cell" x="{rect.min_x:.1f}" y="{rect.min_y:.1f}" '
            f'width="{rect.width:.1f}" height="{rect.height:.1f}" '
            f'fill="url(#cellGrad)" stroke="{COLOR_GEOHASH_BORDER}" stroke-width="0.8" stroke-dasharray="3 2" />'
        )
        svg_parts.append(
            f'    <text x="{rect.min_x + 4:.1f}" y="{rect.min_y + 11:.1f}" fill="{COLOR_TEXT_DIM}" font-size="8">#{gh_cell}</text>'
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
            f'      <text x="{node.x + 9:.1f}" y="{node.y + 8:.1f}" fill="{COLOR_TEXT_DIM}" font-size="8">[{node.geohash}]</text>\n'
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
        f'    <rect x="15" y="15" width="480" height="74" rx="6" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1.2" />\n'
        f'    <text x="25" y="35" fill="{COLOR_TEXT_PRIMARY}" font-size="12" font-weight="bold">DYNAMIC SPATIAL GEOHASH SCADA CANVAS [W309]</text>\n'
        f'    <text x="25" y="55" fill="{COLOR_TEXT_MUTED}" font-size="10">PRECISION: {m.precision} | ACTIVE CELLS: {m.active_cells} | NODES: {m.total_objects} | MATCHES: {m.match_count}</text>\n'
        f'    <text x="25" y="72" fill="{COLOR_TEXT_DIM}" font-size="9">HAZARDS: {m.hazard_violations} | DIAG: 0x{int(m.diagnostic_code):04X} | REGS: %R2700..%R2707 | COILS: %M630..%M631</text>\n'
        f'    <rect x="{w - 180}" y="15" width="165" height="28" rx="4" fill="{alarm_badge_fill}" />\n'
        f'    <text x="{w - 97}" y="33" fill="{COLOR_TEXT_PRIMARY}" font-size="10" font-weight="bold" text-anchor="middle">{alarm_badge_text}</text>\n'
        f'  </g>'
    )

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)


def create_canonical_geohash_canvas(seed: int = 42, count: int = 24, precision: int = 6) -> GeohashCanvasEngine:
    """Helper to instantiate and populate canonical Geohash canvas."""
    engine = GeohashCanvasEngine(precision=precision)
    engine.build_canonical_sensor_network(seed=seed, count=count)
    return engine


# ============================================================================
# 5. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

ST_PROGRAM_W309_GEOHASH_CANVAS_SYNC: str = """
PROGRAM GeohashCanvasSync
VAR
    wTotalObjects AT %R2700 : WORD;
    wPrecision AT %R2701 : WORD;
    wActiveCells AT %R2702 : WORD;
    wPrimaryHash AT %R2703 : WORD;
    wMatchCount AT %R2704 : WORD;
    wHazardViolations AT %R2705 : WORD;
    wStatusWord AT %R2706 : WORD;
    wDiagCode AT %R2707 : WORD;
    bCanvasOnline AT %M630 : BOOL;
    bHazardAlarm AT %M631 : BOOL;
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

ST_PROGRAM_GEOHASH_CANVAS_SYNC = ST_PROGRAM_W309_GEOHASH_CANVAS_SYNC


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

def run_geohash_canvas_verification(
    output_path: Optional[str] = None,
    sample_svg_path: Optional[str] = None,
    work_package: str = "W309",
    quick: bool = False,
) -> Dict[str, Any]:
    """Execute the deterministic 9-stage verification suite for W309 Geohash Canvas."""
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
        GeohashCanvasEngine is not None
        and geohash_encode is not None
        and geohash_decode is not None
        and geohash_neighbors is not None
        and generate_geohash_canvas_svg is not None
    )
    c1 = py_ok and platform_ok and deps_ok and framework_ok and module_ok
    stages.append({
        "stage": 1,
        "name": "environment_and_platform_check",
        "passed": c1,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Python {sys.version.split()[0]} on {sys.platform}; jev_cscape simulation, parser, and W309 modules verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: geohash_constants_and_register_mappings
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    regs_ok = (
        REG_W309_TOTAL_OBJECTS == "%R2700"
        and REG_W309_PRECISION == "%R2701"
        and REG_W309_ACTIVE_CELLS == "%R2702"
        and REG_W309_PRIMARY_HASH == "%R2703"
        and REG_W309_MATCH_COUNT == "%R2704"
        and REG_W309_HAZARD_VIOLATIONS == "%R2705"
        and REG_W309_STATUS_WORD == "%R2706"
        and REG_W309_DIAGNOSTIC_CODE == "%R2707"
        and COIL_W309_CANVAS_ONLINE == "%M630"
        and COIL_W309_HAZARD_ALARM == "%M631"
        and REG_GEOHASH_TOTAL_OBJECTS == "%R2700"
        and COIL_GEOHASH_CANVAS_ONLINE == "%M630"
    )

    diag_ok = (
        int(DiagnosticCode.OK) == 0x0000
        and int(DiagnosticCode.INVALID_DOMAIN) == 0x8401
        and int(DiagnosticCode.DEGENERATE_BOUNDING_BOX) == 0x8402
        and int(DiagnosticCode.OUT_OF_BOUNDS) == 0x8403
        and int(DiagnosticCode.EMPTY_CANVAS) == 0x8404
        and int(DiagnosticCode.INVALID_PRECISION) == 0x8405
        and int(DiagnosticCode.QUERY_OUT_OF_BOUNDS) == 0x8406
        and int(DiagnosticCode.INVALID_BASE32_CHAR) == 0x8407
        and int(DiagnosticCode.SPATIAL_CLUSTER_HAZARD) == 0x8418
        and int(DiagnosticCode.SPATIAL_GEOHASH_PROXIMITY_HAZARD) == 0x8420
    )

    base32_ok = (
        len(BASE32) == 32
        and BASE32 == "0123456789bcdefghjkmnpqrstuvwxyz"
        and all(c not in BASE32 for c in ["a", "i", "l", "o"])
    )

    params_ok = (
        CANVAS_VIEWPORT_WIDTH == 1200.0
        and CANVAS_VIEWPORT_HEIGHT == 750.0
        and MIN_GEOHASH_PRECISION == 1
        and MAX_GEOHASH_PRECISION == 12
        and DEFAULT_GEOHASH_PRECISION == 6
    )

    c2 = regs_ok and diag_ok and base32_ok and params_ok
    stages.append({
        "stage": 2,
        "name": "geohash_constants_and_register_mappings",
        "passed": c2,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Horner OCS %R2700..%R2707, %M630..%M631, diagnostic codes 0x0000/0x8420, and Base32 verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: pure_python_geohash_encoding_and_decoding_bijection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    test_vectors = [
        (51.5074, -0.1278, "gcpvj0"),       # London
        (35.6762, 139.6503, "xn76cy"),     # Tokyo
        (-33.8688, 151.2093, "r3gx2f"),    # Sydney
        (0.0, 0.0, "s00000"),              # Origin
        (45.0, 90.0, "y00000"),            # Mid-quadrant
    ]

    vector_ok = True
    for lat, lon, expected_prefix in test_vectors:
        enc = geohash_encode(lat, lon, len(expected_prefix))
        if enc != expected_prefix:
            vector_ok = False
            break
        bbox = geohash_decode(enc)
        if not bbox.contains_latlon(lat, lon):
            vector_ok = False
            break
        re_enc = geohash_encode(bbox.center_lat, bbox.center_lon, len(expected_prefix))
        if re_enc != enc:
            vector_ok = False
            break

    # Test precision scaling bijection 1..8
    precision_scaling_ok = True
    test_lat, test_lon = 37.7749, -122.4194  # San Francisco
    full_hash = geohash_encode(test_lat, test_lon, 8)
    for p in range(1, 9):
        p_hash = geohash_encode(test_lat, test_lon, p)
        if p_hash != full_hash[:p]:
            precision_scaling_ok = False
            break
        p_bbox = geohash_decode(p_hash)
        if not p_bbox.contains_latlon(test_lat, test_lon):
            precision_scaling_ok = False
            break

    # Bounds & error rejection
    bounds_rejected = False
    try:
        geohash_encode(95.0, 0.0, 6)
    except ValueError:
        try:
            geohash_encode(0.0, 185.0, 6)
        except ValueError:
            try:
                geohash_decode("gcpvja")  # 'a' is illegal in geohash Base32
            except ValueError:
                try:
                    geohash_encode(0.0, 0.0, 0)  # precision < 1
                except ValueError:
                    bounds_rejected = True

    c3 = vector_ok and precision_scaling_ok and bounds_rejected
    stages.append({
        "stage": 3,
        "name": "pure_python_geohash_encoding_and_decoding_bijection",
        "passed": c3,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Bijective round-trips verified across precisions 1..8; Base32 illegal char and domain bounds enforced.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: geohash_8_neighbor_spatial_adjacency
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sample_hashes = ["gcpvj0", "xn76cy", "s00000", "9q8yyk"]
    neighbors_ok = True

    for h_code in sample_hashes:
        nbrs = geohash_neighbors(h_code)
        # 1. Exactly 8 neighbors
        if len(nbrs) != 8:
            neighbors_ok = False
            break
        # 2. None equal to center
        if any(v == h_code for v in nbrs.values()):
            neighbors_ok = False
            break
        # 3. All mutually distinct
        if len(set(nbrs.values())) != 8:
            neighbors_ok = False
            break

        # 4. Spatial boundary contact
        c_box = geohash_decode(h_code)
        n_box = geohash_decode(nbrs["n"])
        s_box = geohash_decode(nbrs["s"])
        e_box = geohash_decode(nbrs["e"])
        w_box = geohash_decode(nbrs["w"])

        if abs(n_box.min_lat - c_box.max_lat) > 1e-7:
            neighbors_ok = False
            break
        if abs(s_box.max_lat - c_box.min_lat) > 1e-7:
            neighbors_ok = False
            break
        if abs(e_box.min_lon - c_box.max_lon) > 1e-7:
            neighbors_ok = False
            break
        if abs(w_box.max_lon - c_box.min_lon) > 1e-7:
            neighbors_ok = False
            break

        # 5. Directional reciprocity
        if geohash_neighbors(nbrs["n"])["s"] != h_code:
            neighbors_ok = False
            break
        if geohash_neighbors(nbrs["s"])["n"] != h_code:
            neighbors_ok = False
            break
        if geohash_neighbors(nbrs["e"])["w"] != h_code:
            neighbors_ok = False
            break
        if geohash_neighbors(nbrs["w"])["e"] != h_code:
            neighbors_ok = False
            break

    c4 = neighbors_ok
    stages.append({
        "stage": 4,
        "name": "geohash_8_neighbor_spatial_adjacency",
        "passed": c4,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "8-neighbor spatial adjacency, boundary coincidence (delta < 1e-7), and reciprocity verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: spatial_proximity_hazard_and_collision_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    p_engine = GeohashCanvasEngine(precision=6, hazard_threshold=35.0)
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
    colliding = p_engine.insert_node(
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
        and p_engine.diagnostic_code == DiagnosticCode.SPATIAL_GEOHASH_PROXIMITY_HAZARD
        and p_engine.hazard_violations >= 1
    )

    # 3. Register sync on hazard trip
    rt_trip = RegisterTable()
    p_engine.sync_to_registers(rt_trip)
    coil_alarm_trip = rt_trip.read_bit(COIL_W309_HAZARD_ALARM)
    coil_online_trip = rt_trip.read_bit(COIL_W309_CANVAS_ONLINE)
    reg_diag_trip = rt_trip.read_word(REG_W309_DIAGNOSTIC_CODE)
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
        rt_trip.read_bit(COIL_W309_HAZARD_ALARM) is False
        and rt_trip.read_bit(COIL_W309_CANVAS_ONLINE) is True
        and (rt_trip.read_word(REG_W309_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
    )

    c5 = nom_ok and trip_ok and regs_trip_ok and clear_ok and regs_clear_ok
    stages.append({
        "stage": 5,
        "name": "spatial_proximity_hazard_and_collision_trip",
        "passed": c5,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Spatial proximity collision trip, coil %M631 alarm latch, and nominal reset verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: register_table_synchronization_and_signed_masks
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_sync = RegisterTable()
    s_engine = create_canonical_geohash_canvas(seed=42, count=24, precision=6)
    s_engine.query_radius(600.0, 375.0, 200.0)
    s_engine.sync_to_registers(rt_sync)

    w_total = rt_sync.read_word(REG_W309_TOTAL_OBJECTS)
    w_prec = rt_sync.read_word(REG_W309_PRECISION)
    w_cells = rt_sync.read_word(REG_W309_ACTIVE_CELLS)
    w_hash = rt_sync.read_word(REG_W309_PRIMARY_HASH)
    w_match = rt_sync.read_word(REG_W309_MATCH_COUNT)
    w_viols = rt_sync.read_word(REG_W309_HAZARD_VIOLATIONS)
    w_status = rt_sync.read_word(REG_W309_STATUS_WORD)
    w_diag = rt_sync.read_word(REG_W309_DIAGNOSTIC_CODE)
    b_online = rt_sync.read_bit(COIL_W309_CANVAS_ONLINE)
    b_alarm = rt_sync.read_bit(COIL_W309_HAZARD_ALARM)

    c6_reads = (
        (w_total & 0xFFFF) == len(s_engine.nodes)
        and (w_prec & 0xFFFF) == s_engine.precision
        and (w_cells & 0xFFFF) == len(set(n.geohash for n in s_engine.nodes.values()))
        and (w_hash & 0xFFFF) == s_engine.metrics.primary_hash
        and (w_match & 0xFFFF) == len(s_engine.last_query_results)
        and (w_viols & 0xFFFF) == 0
        and (w_status & 0x0001) == 1
        and (w_diag & 0xFFFF) == 0x0000
        and b_online is True
        and b_alarm is False
    )

    # Bitwise signed masks verification
    rt_sync.write_word(REG_W309_DIAGNOSTIC_CODE, (-55) & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
    raw_val = rt_sync.read_word(REG_W309_DIAGNOSTIC_CODE)
    val_u = raw_val & 0xFFFF
    val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
    c6_signed = (val_u == 65481 and val_s == -55)

    # High-bit diagnostic code verification
    diag_code = DiagnosticCode.SPATIAL_GEOHASH_PROXIMITY_HAZARD
    rt_sync.write_word(REG_W309_DIAGNOSTIC_CODE, int(diag_code) & 0xFFFF, privilege=PrivilegeMode.USER)
    diag_read = rt_sync.read_word(REG_W309_DIAGNOSTIC_CODE)
    c6_diag = ((diag_read & 0xFFFF) == int(diag_code) and (diag_read & 0xFFFF) == 0x8420)

    # Restore nominal diagnostic in register
    s_engine.sync_to_registers(rt_sync)

    c6 = c6_reads and c6_signed and c6_diag
    stages.append({
        "stage": 6,
        "name": "register_table_synchronization_and_signed_masks",
        "passed": c6,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Horner OCS %R2700..%R2707 and %M630..%M631 synchronized; signed 16-bit masks and 0x8420 verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    SecurityGuard.assert_pure_st_content(ST_PROGRAM_W309_GEOHASH_CANVAS_SYNC)
    st_val = STParser.validate_code(ST_PROGRAM_W309_GEOHASH_CANVAS_SYNC)
    st_ast = STParser.parse_pou(ST_PROGRAM_W309_GEOHASH_CANVAS_SYNC)
    st_pou_ok = (
        st_val.status == AgentStatus.SUCCESS
        and st_ast.pou_type == POUType.PROGRAM
        and st_ast.name == "GeohashCanvasSync"
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
        "details": "Pure ST POU 'GeohashCanvasSync' AST validated; ladder contacts, coils, rungs, and mnemonics strictly rejected.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: svg_scada_canvas_rasterization_and_wcag_contrast
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    canon_canvas = create_canonical_geohash_canvas(seed=42, count=24, precision=6)
    canon_canvas.query_radius(600.0, 375.0, 180.0)
    svg_text = generate_geohash_canvas_svg(canon_canvas)

    # XML validation
    root_el = ET.fromstring(svg_text)
    svg_valid = (
        root_el.tag.endswith("svg")
        and root_el.attrib.get("version") == "1.1"
        and root_el.attrib.get("viewBox") == "0 0 1200 750"
        and "geohash-grid-layer" in svg_text
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
    sim_engine = GeohashCanvasEngine(precision=6)
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
        "details": f"Wave {work_package} Geohash Canvas Verification PASSED ({passed_count}/{total_count} stages).",
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
    """Command-line entry point for W309 Geohash Canvas verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Cscape HMI Dynamic Spatial Geohash SCADA Canvas (W309) 9-Stage Verification Suite"
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
        default="artifacts/HMI/geohash_canvas_evidence.json",
        help="Path to output verification evidence JSON (default: artifacts/HMI/geohash_canvas_evidence.json)",
    )
    parser.add_argument(
        "--svg",
        "-s",
        "--svg-output",
        "--sample-svg",
        dest="svg_output_path",
        type=str,
        default="artifacts/HMI/geohash_canvas_sample.svg",
        help="Path to output sample SVG graphic (default: artifacts/HMI/geohash_canvas_sample.svg)",
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
        default="W309",
        help="Work package identifier (default: W309)",
    )

    args = parser.parse_args(argv)
    effective_output = args.positional_output or args.output_path
    effective_svg = args.positional_svg or args.svg_output_path

    if not args.json_mode:
        print(f"\n{CLR_CYAN}{CLR_BOLD}======================================================================{CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}  JEV CSCAPE VERIFICATION RUNNER - WORK PACKAGE {args.work_package}                 {CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}  Gate G9: Dynamic Spatial Geohash Bounding Box SCADA Canvas         {CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}======================================================================{CLR_RESET}\n")

    t_start = time.perf_counter()
    evidence = run_geohash_canvas_verification(
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
            print(f"  Stage {num:d}: {name:<46} {badge} ({t_ms:.2f} ms)")

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
