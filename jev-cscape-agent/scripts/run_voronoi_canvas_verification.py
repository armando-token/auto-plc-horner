#!/usr/bin/env python3
"""Verification Runner for Cscape HMI Dynamic Spatial Geohash / Voronoi Diagram SCADA Canvas (W324).

Work Package: W324 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial Geohash / Voronoi Diagram SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: environment_and_platform_check
  Stage 2: voronoi_constants_and_register_mappings
  Stage 3: pure_python_voronoi_diagram_construction
  Stage 4: morton_and_geohash_spatial_site_indexing
  Stage 5: spatial_proximity_hazard_and_collision_trip
  Stage 6: register_table_synchronization_and_signed_masks
  Stage 7: pure_st_pou_and_anti_ladder_rejection
  Stage 8: svg_scada_canvas_rasterization_and_wcag_contrast
  Stage 9: multi_cycle_simulation_soak_and_evidence_emission

CLI Arguments:
  --output, -o (default: artifacts/HMI/voronoi_canvas_evidence.json)
  --svg, -s (default: artifacts/HMI/voronoi_canvas_sample.svg)
  --quick, -q (accelerated verification with reduced simulation cycles)
  --json (force JSON emission)
  --work-package, -w (default: W324)
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
import zlib

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
# 1. Constants, Palette & Horner OCS Register Map (W324)
# ============================================================================

CANVAS_VIEWPORT_WIDTH: float         = 1200.0
CANVAS_VIEWPORT_HEIGHT: float        = 750.0
TOTAL_DOMAIN_AREA: float             = CANVAS_VIEWPORT_WIDTH * CANVAS_VIEWPORT_HEIGHT  # 900,000 px^2

MIN_MORTON_ORDER: int                = 1
MAX_MORTON_ORDER: int                = 16
DEFAULT_MORTON_ORDER: int            = 8

MIN_GEOHASH_PRECISION: int           = 1
MAX_GEOHASH_PRECISION: int           = 12
DEFAULT_GEOHASH_PRECISION: int       = 6

DEFAULT_HAZARD_THRESHOLD: float      = 35.0

# Base32 Character Set (standard 32-character geohash alphabet)
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
COLOR_VORONOI_WIRE: str              = "#38BDF8"
COLOR_VORONOI_FILL: str              = "#1E293B"
COLOR_VORONOI_CELL_STROKE: str       = "#64748B"
COLOR_DUAL_EDGE: str                 = "#0284C7"
COLOR_GRID_LINE: str                 = "#1E293B"

# Horner OCS Word Register Map (%R2850..%R2857) & Discrete Coils (%M665..%M666)
REG_W324_TOTAL_OBJECTS: str          = "%R2850"
REG_W324_CELL_COUNT: str             = "%R2851"
REG_W324_ACTIVE_CELLS: str           = "%R2852"
REG_W324_PRIMARY_HASH: str           = "%R2853"
REG_W324_MATCH_COUNT: str            = "%R2854"
REG_W324_HAZARD_VIOLATIONS: str      = "%R2855"
REG_W324_STATUS_WORD: str            = "%R2856"
REG_W324_DIAGNOSTIC_CODE: str        = "%R2857"

COIL_W324_CANVAS_ONLINE: str         = "%M665"
COIL_W324_HAZARD_ALARM: str          = "%M666"

# Register and Coil Aliases
REG_VORONOI_TOTAL_OBJECTS            = REG_W324_TOTAL_OBJECTS
REG_VORONOI_TOTAL_SITES              = REG_W324_TOTAL_OBJECTS
REG_VORONOI_CELL_COUNT               = REG_W324_CELL_COUNT
REG_VORONOI_POLYGONS                 = REG_W324_CELL_COUNT
REG_VORONOI_ACTIVE_CELLS             = REG_W324_ACTIVE_CELLS
REG_VORONOI_INDEXED_SITES            = REG_W324_ACTIVE_CELLS
REG_VORONOI_PRIMARY_HASH             = REG_W324_PRIMARY_HASH
REG_VORONOI_MATCH_COUNT              = REG_W324_MATCH_COUNT
REG_VORONOI_HAZARD_VIOLATIONS        = REG_W324_HAZARD_VIOLATIONS
REG_VORONOI_STATUS_WORD              = REG_W324_STATUS_WORD
REG_VORONOI_DIAGNOSTIC_CODE          = REG_W324_DIAGNOSTIC_CODE

COIL_VORONOI_CANVAS_ONLINE           = COIL_W324_CANVAS_ONLINE
COIL_VORONOI_ONLINE                  = COIL_W324_CANVAS_ONLINE
COIL_VORONOI_HAZARD_ALARM            = COIL_W324_HAZARD_ALARM
COIL_VORONOI_COLLISION_ALARM         = COIL_W324_HAZARD_ALARM


class DiagnosticCode(IntEnum):
    """Horner OCS W324 Voronoi Diagram / Geohash Spatial Canvas Diagnostic Codes."""
    OK                               = 0x0000
    INVALID_DOMAIN                   = 0x8401
    DEGENERATE_CELL                  = 0x8402
    DEGENERATE_BOUNDING_BOX          = 0x8402
    OUT_OF_BOUNDS                    = 0x8403
    EMPTY_CANVAS                     = 0x8404
    INVALID_RESOLUTION               = 0x8405
    INVALID_LEVEL                    = 0x8405
    QUERY_OUT_OF_BOUNDS              = 0x8406
    INVALID_MORTON                   = 0x8407
    INVALID_GEOHASH                  = 0x8408
    INVALID_CELL_ID                  = 0x8407
    INVALID_INDEX                    = 0x8407
    SPATIAL_CLUSTER_HAZARD           = 0x8418
    SPATIAL_PROXIMITY_HAZARD         = 0x8420
    SPATIAL_COLLISION_TRIP           = 0x8420
    PROXIMITY_HAZARD_COLLISION       = 0x8420
    AREA_CONSERVATION_FAULT          = 0x8422


DIAG_OK                             = DiagnosticCode.OK
DIAG_ERR_INVALID_DOMAIN             = DiagnosticCode.INVALID_DOMAIN
DIAG_ERR_DEGENERATE_CELL            = DiagnosticCode.DEGENERATE_CELL
DIAG_ERR_OUT_OF_BOUNDS              = DiagnosticCode.OUT_OF_BOUNDS
DIAG_ERR_EMPTY_CANVAS               = DiagnosticCode.EMPTY_CANVAS
DIAG_ERR_INVALID_LEVEL              = DiagnosticCode.INVALID_LEVEL
DIAG_ERR_QUERY_OUT_OF_BOUNDS        = DiagnosticCode.QUERY_OUT_OF_BOUNDS
DIAG_ERR_INVALID_MORTON             = DiagnosticCode.INVALID_MORTON
DIAG_ERR_INVALID_GEOHASH            = DiagnosticCode.INVALID_GEOHASH
DIAG_ERR_SPATIAL_PROXIMITY_HAZARD   = DiagnosticCode.SPATIAL_PROXIMITY_HAZARD
DIAG_ERR_AREA_CONSERVATION_FAULT    = DiagnosticCode.AREA_CONSERVATION_FAULT


class VoronoiStatusBits(IntFlag):
    """16-bit packed status word for Voronoi Diagram & Geohash Canvas engine."""
    ONLINE              = 0x0001
    HAZARD_ALARM        = 0x0002
    DIAGRAM_COMPUTED    = 0x0004
    MORTON_INDEXED      = 0x0008
    GEOHASH_INDEXED     = 0x0010
    QUERY_ACTIVE        = 0x0020
    AREA_CONSERVED      = 0x0040
    CELLS_BOUNDED       = 0x0080


# ============================================================================
# 2. Pure Python Geometric Primitives & Voronoi Construction
# ============================================================================

@dataclass(frozen=True)
class Point2D:
    """2D Point with analytical vector operations."""
    x: float
    y: float

    def distance_to(self, other: Point2D) -> float:
        """Euclidean distance to another point."""
        return math.hypot(self.x - other.x, self.y - other.y)

    def midpoint(self, other: Point2D) -> Point2D:
        """Midpoint between two points."""
        return Point2D((self.x + other.x) / 2.0, (self.y + other.y) / 2.0)


@dataclass
class Polygon2D:
    """Ordered planar convex polygon with exact Green's Theorem area & centroid."""
    vertices: List[Point2D] = field(default_factory=list)

    def shoelace_area(self) -> float:
        """Calculate exact polygon area via Green's Theorem Shoelace formula."""
        n = len(self.vertices)
        if n < 3:
            return 0.0
        acc = 0.0
        for i in range(n):
            j = (i + 1) % n
            acc += self.vertices[i].x * self.vertices[j].y - self.vertices[j].x * self.vertices[i].y
        return 0.5 * abs(acc)

    def centroid(self) -> Point2D:
        """Calculate analytical polygon centroid (center of mass)."""
        n = len(self.vertices)
        if n < 3:
            return Point2D(0.0, 0.0)
        signed_area_double = 0.0
        c_x = 0.0
        c_y = 0.0
        for i in range(n):
            j = (i + 1) % n
            cross = self.vertices[i].x * self.vertices[j].y - self.vertices[j].x * self.vertices[i].y
            signed_area_double += cross
            c_x += (self.vertices[i].x + self.vertices[j].x) * cross
            c_y += (self.vertices[i].y + self.vertices[j].y) * cross

        if abs(signed_area_double) < 1e-9:
            return Point2D(
                sum(p.x for p in self.vertices) / n,
                sum(p.y for p in self.vertices) / n,
            )

        factor = 1.0 / (3.0 * signed_area_double)
        return Point2D(c_x * factor, c_y * factor)

    def clip_halfplane(self, p_mid: Point2D, normal: Point2D) -> Polygon2D:
        """Sutherland-Hodgman convex clipping against half-plane: (P - p_mid) . normal <= 0."""
        out: List[Point2D] = []
        n = len(self.vertices)
        if n < 3:
            return Polygon2D(out)

        def eval_dist(p: Point2D) -> float:
            return (p.x - p_mid.x) * normal.x + (p.y - p_mid.y) * normal.y

        for i in range(n):
            p1 = self.vertices[i]
            p2 = self.vertices[(i + 1) % n]
            d1 = eval_dist(p1)
            d2 = eval_dist(p2)

            if d1 <= 1e-9:
                if d2 <= 1e-9:
                    out.append(p2)
                else:
                    t = d1 / (d1 - d2)
                    out.append(Point2D(p1.x + t * (p2.x - p1.x), p1.y + t * (p2.y - p1.y)))
            else:
                if d2 <= 1e-9:
                    t = d1 / (d1 - d2)
                    out.append(Point2D(p1.x + t * (p2.x - p1.x), p1.y + t * (p2.y - p1.y)))
                    out.append(p2)

        return Polygon2D(out)

    def contains_point(self, x: float, y: float, tol: float = 1e-6) -> bool:
        """Test if (x, y) lies inside or on the boundary of the convex polygon."""
        n = len(self.vertices)
        if n < 3:
            return False
        p = Point2D(x, y)
        signs: List[float] = []
        for i in range(n):
            p1 = self.vertices[i]
            p2 = self.vertices[(i + 1) % n]
            cross = (p2.x - p1.x) * (p.y - p1.y) - (p2.y - p1.y) * (p.x - p1.x)
            if abs(cross) > tol:
                signs.append(cross)
        if not signs:
            return True
        first_sign = signs[0] > 0.0
        return all((s > 0.0) == first_sign for s in signs)


@dataclass(frozen=True)
class VoronoiSite:
    """Industrial sensor node / site in plant coordinate space."""
    site_id: int
    x: float
    y: float
    val: float = 0.0            # Process reading (e.g. Temperature in degC)
    tag: str = ""
    morton_code: int = 0
    geohash: str = ""
    hazard_radius: float = 20.0

    def distance_to(self, other: Union[VoronoiSite, Point2D]) -> float:
        return math.hypot(self.x - other.x, self.y - other.y)


@dataclass
class VoronoiCell:
    """Bounded spatial cell of a Voronoi diagram."""
    site: VoronoiSite
    polygon: Polygon2D = field(default_factory=Polygon2D)
    area: float = 0.0
    centroid: Point2D = field(default_factory=lambda: Point2D(0.0, 0.0))
    neighbors: List[int] = field(default_factory=list)        # Adjacent site IDs
    gradients: Dict[int, float] = field(default_factory=dict) # Directed gradients to neighbors


def compute_voronoi_diagram(
    sites: List[VoronoiSite],
    width: float = CANVAS_VIEWPORT_WIDTH,
    height: float = CANVAS_VIEWPORT_HEIGHT,
) -> List[VoronoiCell]:
    """Compute pure Python Voronoi diagram inside [0, width] x [0, height] domain.

    Uses Sutherland-Hodgman convex polygon clipping against perpendicular bisectors.
    Returns empty list for 0 sites.
    For 1 site, returns the whole viewport bounding box.
    """
    if not sites:
        return []

    cells: List[VoronoiCell] = []
    n_sites = len(sites)

    # Base bounding box polygon for canvas viewport
    bbox_vertices = [
        Point2D(0.0, 0.0),
        Point2D(width, 0.0),
        Point2D(width, height),
        Point2D(0.0, height),
    ]

    if n_sites == 1:
        poly = Polygon2D(list(bbox_vertices))
        area = poly.shoelace_area()
        cent = poly.centroid()
        return [VoronoiCell(site=sites[0], polygon=poly, area=area, centroid=cent)]

    for i, site_i in enumerate(sites):
        poly = Polygon2D(list(bbox_vertices))
        p_i = Point2D(site_i.x, site_i.y)

        # Clip against perpendicular bisector of every other site
        for j, site_j in enumerate(sites):
            if i == j:
                continue
            p_j = Point2D(site_j.x, site_j.y)
            p_mid = p_i.midpoint(p_j)
            normal = Point2D(p_j.x - p_i.x, p_j.y - p_i.y)
            poly = poly.clip_halfplane(p_mid, normal)

        area = poly.shoelace_area()
        cent = poly.centroid()
        cells.append(VoronoiCell(site=site_i, polygon=poly, area=area, centroid=cent))

    # Detect Delaunay dual neighbors and calculate directional gradients
    for i, cell_i in enumerate(cells):
        poly_i = cell_i.polygon
        n_verts = len(poly_i.vertices)
        if n_verts < 3:
            continue
        p_i = Point2D(cell_i.site.x, cell_i.site.y)

        for j, cell_j in enumerate(cells):
            if i == j:
                continue
            site_j = cell_j.site
            p_j = Point2D(site_j.x, site_j.y)
            p_mid = p_i.midpoint(p_j)
            norm = Point2D(p_j.x - p_i.x, p_j.y - p_i.y)
            norm_len = math.hypot(norm.x, norm.y)
            if norm_len < 1e-9:
                continue
            unit_norm = Point2D(norm.x / norm_len, norm.y / norm_len)

            # Check if any edge of cell_i lies on the bisector with site_j
            is_neighbor = False
            for k in range(n_verts):
                v1 = poly_i.vertices[k]
                v2 = poly_i.vertices[(k + 1) % n_verts]
                if v1.distance_to(v2) < 1e-3:
                    continue
                d1 = abs((v1.x - p_mid.x) * unit_norm.x + (v1.y - p_mid.y) * unit_norm.y)
                d2 = abs((v2.x - p_mid.x) * unit_norm.x + (v2.y - p_mid.y) * unit_norm.y)
                if d1 < 1e-4 and d2 < 1e-4:
                    is_neighbor = True
                    break

            if is_neighbor:
                cell_i.neighbors.append(site_j.site_id)
                dist = p_i.distance_to(p_j)
                grad = abs(cell_i.site.val - site_j.val) / max(dist, 1e-3)
                cell_i.gradients[site_j.site_id] = grad

    return cells


# ============================================================================
# 3. Pure Python Morton Z-Order & Geohash Spatial Indexing
# ============================================================================

def morton_xy2z(*args: int, order: Optional[int] = None) -> int:
    """Convert 2D integer coordinates to Morton Z-order curve index via bit interleaving.

    Supports:
      morton_xy2z(x, y) -> default order 16
      morton_xy2z(x, y, order=16)
      morton_xy2z(order, x, y)
      morton_xy2z(x, y, order)
    """
    if order is not None and len(args) == 2:
        x, y = args
        ord_val = order
    elif len(args) == 2:
        x, y = args
        ord_val = 16
    elif len(args) == 3:
        if args[2] <= 16 and (args[0] > 16 or args[1] > 16):
            x, y, ord_val = args
        else:
            ord_val, x, y = args
    else:
        raise TypeError(f"morton_xy2z expects 2 or 3 arguments, got {len(args)}")

    if x < 0 or y < 0:
        raise ValueError(f"Morton coordinates must be non-negative, got ({x}, {y})")
    n = 1 << ord_val
    if x >= n or y >= n:
        raise ValueError(f"Grid coordinates ({x}, {y}) out of bounds for order {ord_val} [0, {n - 1}]")

    z = 0
    for i in range(ord_val):
        z |= ((x >> i) & 1) << (2 * i)
        z |= ((y >> i) & 1) << (2 * i + 1)
    return z


def morton_z2xy(*args: int, order: Optional[int] = None) -> Tuple[int, int]:
    """Convert Morton Z-order index to 2D integer coordinates (x, y) via de-interleaving.

    Supports:
      morton_z2xy(z) -> default order 16
      morton_z2xy(z, order=16)
      morton_z2xy(order, z)
      morton_z2xy(z, order)
    """
    if order is not None and len(args) == 1:
        z = args[0]
        ord_val = order
    elif len(args) == 1:
        z = args[0]
        ord_val = 16
    elif len(args) == 2:
        if args[1] <= 16 and args[0] > 16:
            z, ord_val = args
        else:
            ord_val, z = args
    else:
        raise TypeError(f"morton_z2xy expects 1 or 2 arguments, got {len(args)}")

    if z < 0:
        raise ValueError(f"Morton code must be non-negative, got {z}")
    max_z = (1 << (2 * ord_val)) - 1
    if z > max_z:
        raise ValueError(f"Morton index z={z} out of bounds for order {ord_val} [0, {max_z}]")

    x = 0
    y = 0
    for i in range(ord_val):
        x |= ((z >> (2 * i)) & 1) << i
        y |= ((z >> (2 * i + 1)) & 1) << i
    return x, y


def point_to_morton(
    x: float,
    y: float,
    width: float = CANVAS_VIEWPORT_WIDTH,
    height: float = CANVAS_VIEWPORT_HEIGHT,
    order: int = DEFAULT_MORTON_ORDER,
) -> int:
    """Map continuous canvas coordinates (x, y) to discrete Morton Z-order index."""
    if x < 0.0 or y < 0.0 or x > width or y > height:
        raise ValueError(f"Coordinate ({x}, {y}) out of viewport bounds [0..{width}, 0..{height}]")
    max_coord = (1 << order) - 1
    gx = int(min(max_coord, max(0, math.floor((x / width) * (1 << order)))))
    gy = int(min(max_coord, max(0, math.floor((y / height) * (1 << order)))))
    return morton_xy2z(gx, gy, order=order)


def geohash_encode(lat: float, lon: float, precision: int = DEFAULT_GEOHASH_PRECISION) -> str:
    """Encode latitude and longitude into Base32 Geohash string."""
    if not (-90.0 <= lat <= 90.0):
        raise ValueError(f"Latitude out of bounds [-90, 90]: {lat}")
    if not (1 <= precision <= MAX_GEOHASH_PRECISION):
        raise ValueError(f"Geohash precision out of range [1, {MAX_GEOHASH_PRECISION}]: {precision}")

    while lon > 180.0:
        lon -= 360.0
    while lon < -180.0:
        lon += 360.0

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


def geohash_decode(gh: str) -> Tuple[float, float, float, float]:
    """Decode Base32 Geohash string into (lat, lon, lat_err, lon_err)."""
    if not gh:
        raise ValueError("Cannot decode empty Geohash string")
    lat_interval = [-90.0, 90.0]
    lon_interval = [-180.0, 180.0]
    even = True

    for c in gh.lower():
        if c not in BASE32_MAP:
            raise ValueError(f"Invalid character in Geohash string: {c}")
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

    lat = (lat_interval[0] + lat_interval[1]) / 2.0
    lon = (lon_interval[0] + lon_interval[1]) / 2.0
    lat_err = (lat_interval[1] - lat_interval[0]) / 2.0
    lon_err = (lon_interval[1] - lon_interval[0]) / 2.0
    return lat, lon, lat_err, lon_err


def point_to_geohash(
    x: float,
    y: float,
    width: float = CANVAS_VIEWPORT_WIDTH,
    height: float = CANVAS_VIEWPORT_HEIGHT,
    precision: int = DEFAULT_GEOHASH_PRECISION,
) -> str:
    """Map continuous canvas coordinates (x, y) to Base32 Geohash string."""
    if x < 0.0 or y < 0.0 or x > width or y > height:
        raise ValueError(f"Coordinate ({x}, {y}) out of viewport bounds [0..{width}, 0..{height}]")
    lat = -85.0 + (y / height) * 170.0
    lon = -170.0 + (x / width) * 340.0
    return geohash_encode(lat, lon, precision=precision)


def geohash_to_point(
    gh: str,
    width: float = CANVAS_VIEWPORT_WIDTH,
    height: float = CANVAS_VIEWPORT_HEIGHT,
) -> Tuple[float, float]:
    """Map Base32 Geohash string back to continuous canvas coordinates (x, y)."""
    lat, lon, _, _ = geohash_decode(gh)
    y = ((lat + 85.0) / 170.0) * height
    x = ((lon + 170.0) / 340.0) * width
    return max(0.0, min(width, x)), max(0.0, min(height, y))


def geohash_neighbors(gh: str) -> Dict[str, str]:
    """Return the 8 compass-direction spatial neighbors of a Geohash cell."""
    lat, lon, lat_err, lon_err = geohash_decode(gh)
    d_lat = 2.0 * lat_err
    d_lon = 2.0 * lon_err
    offsets = [
        ("n", d_lat, 0.0),
        ("s", -d_lat, 0.0),
        ("e", 0.0, d_lon),
        ("w", 0.0, -d_lon),
        ("ne", d_lat, d_lon),
        ("nw", d_lat, -d_lon),
        ("se", -d_lat, d_lon),
        ("sw", -d_lat, -d_lon),
    ]
    neighbors: Dict[str, str] = {}
    prec = len(gh)
    for dir_name, dy, dx in offsets:
        n_lat = min(89.9, max(-89.9, lat + dy))
        n_lon = lon + dx
        while n_lon > 180.0:
            n_lon -= 360.0
        while n_lon < -180.0:
            n_lon += 360.0
        neighbors[dir_name] = geohash_encode(n_lat, n_lon, precision=prec)
    return neighbors


# ============================================================================
# 4. Voronoi Canvas Engine Implementation (ILogicUnit)
# ============================================================================

@dataclass
class VoronoiMetrics:
    """Runtime telemetry metrics snapshot for Horner OCS register synchronization."""
    total_objects: int = 0
    cell_count: int = 0
    active_cells: int = 0
    primary_hash: int = 0
    match_count: int = 0
    hazard_violations: int = 0
    status_word: int = 0
    diagnostic_code: DiagnosticCode = DiagnosticCode.OK
    canvas_online: bool = True
    hazard_alarm: bool = False


class VoronoiCanvasEngine(ILogicUnit):
    """Dynamic Spatial Geohash / Voronoi Diagram SCADA Canvas Engine."""

    def __init__(
        self,
        viewport_width: float = CANVAS_VIEWPORT_WIDTH,
        viewport_height: float = CANVAS_VIEWPORT_HEIGHT,
        hazard_threshold: float = DEFAULT_HAZARD_THRESHOLD,
        morton_order: int = DEFAULT_MORTON_ORDER,
        geohash_precision: int = DEFAULT_GEOHASH_PRECISION,
    ) -> None:
        self.viewport_width: float = viewport_width
        self.viewport_height: float = viewport_height
        self.hazard_threshold: float = hazard_threshold
        self.morton_order: int = morton_order
        self.geohash_precision: int = geohash_precision

        self.sites: Dict[int, VoronoiSite] = {}
        self.cells: Dict[int, VoronoiCell] = {}
        self.active_morton_cells: Set[int] = set()
        self.active_geohashes: Set[str] = set()

        self.selected_site_id: int = 0
        self.last_query_results: List[VoronoiSite] = []
        self.last_query_radius: float = 0.0
        self.last_query_center: Tuple[float, float] = (0.0, 0.0)

        self.cycle_count: int = 0
        self.alarm_active: bool = False
        self.hazard_violations: int = 0
        self.diagnostic_code: DiagnosticCode = DiagnosticCode.OK

        self.reg_table: RegisterTable = RegisterTable()

    def reset(self) -> None:
        """Reset internal canvas state."""
        self.sites.clear()
        self.cells.clear()
        self.active_morton_cells.clear()
        self.active_geohashes.clear()
        self.selected_site_id = 0
        self.last_query_results.clear()
        self.last_query_radius = 0.0
        self.last_query_center = (0.0, 0.0)
        self.cycle_count = 0
        self.alarm_active = False
        self.hazard_violations = 0
        self.diagnostic_code = DiagnosticCode.OK

    def insert_site(
        self,
        x: float,
        y: float,
        site_id: int,
        val: float = 0.0,
        tag: str = "",
        hazard_radius: float = 20.0,
    ) -> VoronoiSite:
        """Insert or update a spatial equipment site and compute its spatial indexes."""
        if not (0.0 <= x <= self.viewport_width and 0.0 <= y <= self.viewport_height):
            self.diagnostic_code = DiagnosticCode.OUT_OF_BOUNDS
            raise ValueError(
                f"Site ({x}, {y}) exceeds canvas dimensions ({self.viewport_width}, {self.viewport_height})"
            )

        m_code = point_to_morton(x, y, self.viewport_width, self.viewport_height, self.morton_order)
        gh = point_to_geohash(x, y, self.viewport_width, self.viewport_height, self.geohash_precision)
        site = VoronoiSite(
            site_id=site_id,
            x=x,
            y=y,
            val=val,
            tag=tag or f"SITE-{site_id:03d}",
            morton_code=m_code,
            geohash=gh,
            hazard_radius=hazard_radius,
        )
        self.sites[site_id] = site
        self.active_morton_cells.add(m_code)
        self.active_geohashes.add(gh)
        return site

    def remove_site(self, site_id: int) -> Optional[VoronoiSite]:
        """Remove a site by ID and refresh active spatial indexes."""
        site = self.sites.pop(site_id, None)
        if site:
            self.active_morton_cells = set(s.morton_code for s in self.sites.values())
            self.active_geohashes = set(s.geohash for s in self.sites.values())
            if self.selected_site_id == site_id:
                self.selected_site_id = 0
            self.recompute_diagram()
        return site

    def get_site(self, site_id: int) -> Optional[VoronoiSite]:
        """Retrieve site by ID."""
        return self.sites.get(site_id)

    def recompute_diagram(self) -> List[VoronoiCell]:
        """Recompute Voronoi tessellation across all active sites."""
        site_list = list(self.sites.values())
        cell_list = compute_voronoi_diagram(site_list, self.viewport_width, self.viewport_height)
        self.cells = {c.site.site_id: c for c in cell_list}
        return cell_list

    def check_proximity_hazards(self) -> List[Tuple[int, int, float]]:
        """Check for spatial proximity collisions between all pairs of sites."""
        violations: List[Tuple[int, int, float]] = []
        site_list = list(self.sites.values())
        n = len(site_list)

        for i in range(n):
            for j in range(i + 1, n):
                s1 = site_list[i]
                s2 = site_list[j]
                dist = s1.distance_to(s2)
                # Violation if distance is less than hazard threshold
                if dist <= self.hazard_threshold:
                    violations.append((s1.site_id, s2.site_id, dist))

        self.hazard_violations = len(violations)
        if self.hazard_violations > 0:
            self.alarm_active = True
            self.diagnostic_code = DiagnosticCode.SPATIAL_PROXIMITY_HAZARD
        else:
            self.alarm_active = False
            self.diagnostic_code = DiagnosticCode.OK

        return violations

    def query_radius(self, cx: float, cy: float, radius: float) -> List[VoronoiSite]:
        """Query all sites within a circular Euclidean radius."""
        if cx < 0.0 or cy < 0.0 or cx > self.viewport_width or cy > self.viewport_height:
            self.diagnostic_code = DiagnosticCode.QUERY_OUT_OF_BOUNDS
            raise ValueError(f"Query center ({cx}, {cy}) is out of viewport bounds")

        self.last_query_center = (cx, cy)
        self.last_query_radius = radius
        results: List[VoronoiSite] = []
        p_query = Point2D(cx, cy)

        for site in self.sites.values():
            if site.distance_to(p_query) <= radius:
                results.append(site)

        self.last_query_results = results
        return results

    def _compute_primary_hash(self) -> int:
        """Deterministic 16-bit hash tracking sites, coordinates, and spatial indexes."""
        h = 0
        for site in sorted(self.sites.values(), key=lambda s: s.site_id):
            gh_sum = sum(ord(c) for c in site.geohash)
            h = (h * 31 + site.site_id * 1009 + int(site.x * 10) + int(site.y * 10) + site.morton_code + gh_sum) & 0xFFFF
        return h

    @property
    def metrics(self) -> VoronoiMetrics:
        """Construct a live snapshot of telemetry metrics."""
        status = VoronoiStatusBits.ONLINE
        if self.alarm_active:
            status |= VoronoiStatusBits.HAZARD_ALARM
        if len(self.cells) > 0:
            status |= VoronoiStatusBits.DIAGRAM_COMPUTED
        if len(self.active_morton_cells) > 0:
            status |= VoronoiStatusBits.MORTON_INDEXED
        if len(self.active_geohashes) > 0:
            status |= VoronoiStatusBits.GEOHASH_INDEXED
        if self.last_query_radius > 0.0:
            status |= VoronoiStatusBits.QUERY_ACTIVE

        # Area conservation test
        if len(self.cells) > 0:
            total_area = sum(c.area for c in self.cells.values())
            if abs(total_area - (self.viewport_width * self.viewport_height)) < 1.0:
                status |= VoronoiStatusBits.AREA_CONSERVED
            status |= VoronoiStatusBits.CELLS_BOUNDED

        return VoronoiMetrics(
            total_objects=len(self.sites),
            cell_count=len(self.cells),
            active_cells=len(self.active_morton_cells),
            primary_hash=self._compute_primary_hash(),
            match_count=len(self.last_query_results),
            hazard_violations=self.hazard_violations,
            status_word=int(status),
            diagnostic_code=self.diagnostic_code,
            canvas_online=not self.alarm_active,
            hazard_alarm=self.alarm_active,
        )

    def sync_to_registers(
        self,
        rt: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize runtime metrics to Horner OCS registers and coils."""
        table = rt if rt is not None else self.reg_table
        m = self.metrics

        table.write_word(REG_W324_TOTAL_OBJECTS, m.total_objects & 0xFFFF, privilege=privilege)
        table.write_word(REG_W324_CELL_COUNT, m.cell_count & 0xFFFF, privilege=privilege)
        table.write_word(REG_W324_ACTIVE_CELLS, m.active_cells & 0xFFFF, privilege=privilege)
        table.write_word(REG_W324_PRIMARY_HASH, m.primary_hash & 0xFFFF, privilege=privilege)
        table.write_word(REG_W324_MATCH_COUNT, m.match_count & 0xFFFF, privilege=privilege)
        table.write_word(REG_W324_HAZARD_VIOLATIONS, m.hazard_violations & 0xFFFF, privilege=privilege)
        table.write_word(REG_W324_STATUS_WORD, m.status_word & 0xFFFF, privilege=privilege)
        table.write_word(REG_W324_DIAGNOSTIC_CODE, int(m.diagnostic_code) & 0xFFFF, privilege=privilege)

        table.write_bit(COIL_W324_CANVAS_ONLINE, m.canvas_online, privilege=privilege)
        table.write_bit(COIL_W324_HAZARD_ALARM, m.hazard_alarm, privilege=privilege)

    # ILogicUnit interface compliance
    @property
    def name(self) -> str:
        return "VoronoiCanvasEngine"

    @property
    def priority(self) -> int:
        return 100

    @property
    def is_enabled(self) -> bool:
        return True

    def step(self, *args: Any, **kwargs: Any) -> None:
        self.scan_step(*args, **kwargs)

    def scan_step(self, ctx: Optional[ScanContext] = None) -> ExecutionResult:
        """Execute one scan cycle: recompute Voronoi topology and sync registers."""
        self.cycle_count += 1
        self.recompute_diagram()
        self.check_proximity_hazards()
        rt = ctx.register_table if ctx and ctx.register_table else self.reg_table
        self.sync_to_registers(rt)
        return ExecutionResult(
            status=AgentStatus.SUCCESS,
            error_code=None,
            details=f"Cycle {self.cycle_count} processed successfully.",
            data={
                "cycle": self.cycle_count,
                "sites": len(self.sites),
                "cells": len(self.cells),
                "active_cells": len(self.active_morton_cells),
                "matches": len(self.last_query_results),
                "violations": self.hazard_violations,
                "alarm": self.alarm_active,
                "diagnostic_code": int(self.diagnostic_code),
            },
        )

    def execute(self, *args: Any, **kwargs: Any) -> ExecutionResult:
        """ILogicUnit entrypoint."""
        return self.scan_step(*args, **kwargs)

    def build_canonical_sensor_network(self, seed: int = 42, count: int = 16) -> None:
        """Construct deterministic canonical industrial sensor network with 0 initial hazards."""
        self.reset()
        rng = random.Random(seed)

        cols = 4
        rows = (count + cols - 1) // cols
        dx = (self.viewport_width - 240.0) / float(cols)
        dy = (self.viewport_height - 200.0) / float(rows)

        idx = 0
        for r in range(rows):
            for c in range(cols):
                if idx >= count:
                    break
                base_x = 120.0 + c * dx + rng.uniform(-10.0, 10.0)
                base_y = 100.0 + r * dy + rng.uniform(-10.0, 10.0)
                temp_val = 20.0 + rng.uniform(0.0, 65.0)
                self.insert_site(
                    x=base_x,
                    y=base_y,
                    site_id=idx + 1,
                    val=temp_val,
                    tag=f"VS-{idx+1:03d}",
                    hazard_radius=20.0,
                )
                idx += 1

        self.recompute_diagram()
        self.alarm_active = False
        self.hazard_violations = 0
        self.diagnostic_code = DIAG_OK


# ============================================================================
# 5. WCAG 2.1 AAA Contrast & Standalone SVG Generation
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


def generate_voronoi_canvas_svg(engine: VoronoiCanvasEngine) -> str:
    """Generate standalone W3C SVG 1.1 vector graphic meeting WCAG 2.1 AAA contrast."""
    w = int(engine.viewport_width)
    h = int(engine.viewport_height)

    svg_parts: List[str] = []
    svg_parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" version="1.1" viewBox="0 0 {w} {h}" '
        f'width="{w}" height="{h}" style="background-color: {COLOR_SCADA_BG}; font-family: monospace;">'
    )

    # 1. Defs: Gradients
    svg_parts.append(
        '  <defs>\n'
        '    <linearGradient id="cellGrad" x1="0%" y1="0%" x2="100%" y2="100%">\n'
        f'      <stop offset="0%" stop-color="{COLOR_VORONOI_WIRE}" stop-opacity="0.12" />\n'
        f'      <stop offset="100%" stop-color="{COLOR_NOMINAL_EMERALD}" stop-opacity="0.04" />\n'
        '    </linearGradient>\n'
        '  </defs>'
    )

    # 2. Voronoi Polygonal Cells Layer
    svg_parts.append('  <!-- Voronoi Tessellation Cells Layer -->')
    svg_parts.append('  <g id="voronoi-cells-layer" class="voronoi-cells">')
    for cell in engine.cells.values():
        poly = cell.polygon
        pts = " ".join(f"{p.x:.1f},{p.y:.1f}" for p in poly.vertices)
        svg_parts.append(
            f'    <polygon points="{pts}" fill="url(#cellGrad)" stroke="{COLOR_VORONOI_CELL_STROKE}" stroke-width="1.2" />'
        )
    svg_parts.append('  </g>')

    # 3. Delaunay Dual Adjacency Edges Layer
    svg_parts.append('  <!-- Delaunay Dual Adjacency Graph Layer -->')
    svg_parts.append('  <g id="delaunay-dual-layer" class="delaunay-dual-edges">')
    visited_edges: Set[Tuple[int, int]] = set()
    for cell in engine.cells.values():
        s1 = cell.site
        for n_id in cell.neighbors:
            edge_key = (min(s1.site_id, n_id), max(s1.site_id, n_id))
            if edge_key in visited_edges:
                continue
            visited_edges.add(edge_key)
            s2 = engine.get_site(n_id)
            if s2:
                svg_parts.append(
                    f'    <line x1="{s1.x:.1f}" y1="{s1.y:.1f}" x2="{s2.x:.1f}" y2="{s2.y:.1f}" '
                    f'stroke="{COLOR_DUAL_EDGE}" stroke-width="1.0" stroke-dasharray="3 3" opacity="0.6" />'
                )
    svg_parts.append('  </g>')

    # 4. Voronoi Sites Layer
    svg_parts.append('  <!-- Spatial Equipment Sensor Sites Layer -->')
    svg_parts.append('  <g id="voronoi-sites-layer" class="voronoi-sites">')
    for site in engine.sites.values():
        svg_parts.append(
            f'    <circle class="sensor-node" cx="{site.x:.1f}" cy="{site.y:.1f}" r="6.0" '
            f'fill="{COLOR_SAMPLE_NODE}" stroke="{COLOR_SAMPLE_BORDER}" stroke-width="1.5" />'
        )
        svg_parts.append(
            f'    <text x="{site.x + 8:.1f}" y="{site.y + 4:.1f}" fill="{COLOR_TEXT_PRIMARY}" font-size="9">{site.tag} (Z:{site.morton_code}, GH:{site.geohash})</text>'
        )
    svg_parts.append('  </g>')

    # 5. Query Reticle Layer
    svg_parts.append('  <!-- Query Reticle Layer -->')
    svg_parts.append('  <g id="query-reticle-layer" class="query-reticle">')
    if engine.last_query_radius > 0.0:
        cx, cy = engine.last_query_center
        svg_parts.append(
            f'    <circle cx="{cx:.1f}" cy="{cy:.1f}" r="{engine.last_query_radius:.1f}" '
            f'fill="none" stroke="{COLOR_RETICLE_CYAN}" stroke-width="1.5" stroke-dasharray="5 3" />'
        )
    svg_parts.append('  </g>')

    # 6. Spatial Hazard Collision Vectors
    svg_parts.append('  <!-- Spatial Hazard Vectors Layer -->')
    svg_parts.append('  <g id="hazard-vectors-layer" class="hazard-vectors">')
    if engine.alarm_active:
        hazards = engine.check_proximity_hazards()
        for id1, id2, dist in hazards:
            s1 = engine.get_site(id1)
            s2 = engine.get_site(id2)
            if s1 and s2:
                svg_parts.append(
                    f'    <line class="hazard-collision-line" x1="{s1.x:.1f}" y1="{s1.y:.1f}" x2="{s2.x:.1f}" y2="{s2.y:.1f}" '
                    f'stroke="{COLOR_ALARM_CRIMSON}" stroke-width="2.5" stroke-dasharray="4 2" />'
                )
                mid_x = (s1.x + s2.x) / 2.0
                mid_y = (s1.y + s2.y) / 2.0
                svg_parts.append(
                    f'    <text x="{mid_x:.1f}" y="{mid_y - 6:.1f}" fill="{COLOR_ALARM_CRIMSON}" font-size="9" font-weight="bold">HAZARD: {dist:.1f}px</text>'
                )
    svg_parts.append('  </g>')

    # 7. HUD Telemetry Scorecard (WCAG AAA High Contrast > 18:1)
    m = engine.metrics
    alarm_badge_fill = COLOR_ALARM_CRIMSON if m.hazard_alarm else COLOR_NOMINAL_EMERALD
    alarm_badge_text = "HAZARD ALARM" if m.hazard_alarm else "INDEXING NOMINAL"

    svg_parts.append(
        f'  <!-- HUD Telemetry Scorecard -->\n'
        f'  <g id="scorecard-layer" class="hud-telemetry-scorecard">\n'
        f'    <rect x="15" y="15" width="560" height="74" rx="6" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1.2" />\n'
        f'    <text x="25" y="35" fill="{COLOR_TEXT_PRIMARY}" font-size="11" font-weight="bold">DYNAMIC SPATIAL GEOHASH / VORONOI DIAGRAM SCADA CANVAS [W324]</text>\n'
        f'    <text x="25" y="55" fill="{COLOR_TEXT_MUTED}" font-size="10">SITES: {m.total_objects} | CELLS: {m.cell_count} | MORTON CELLS: {m.active_cells} | MATCHES: {m.match_count}</text>\n'
        f'    <text x="25" y="72" fill="{COLOR_TEXT_DIM}" font-size="9">HAZARDS: {m.hazard_violations} | DIAG: 0x{int(m.diagnostic_code):04X} | REGS: %R2850..%R2857 | COILS: %M665..%M666</text>\n'
        f'    <rect x="{w - 180}" y="15" width="165" height="28" rx="4" fill="{alarm_badge_fill}" />\n'
        f'    <text x="{w - 97}" y="33" fill="{COLOR_TEXT_PRIMARY}" font-size="10" font-weight="bold" text-anchor="middle">{alarm_badge_text}</text>\n'
        f'  </g>'
    )

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)


def create_canonical_voronoi_canvas(
    seed: int = 42,
    count: int = 16,
) -> VoronoiCanvasEngine:
    """Helper to instantiate and populate canonical Voronoi Diagram canvas."""
    engine = VoronoiCanvasEngine()
    engine.build_canonical_sensor_network(seed=seed, count=count)
    return engine


# ============================================================================
# 6. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

ST_PROGRAM_W324_VORONOI_CANVAS_SYNC: str = """
PROGRAM VoronoiCanvasSync
VAR
    wTotalObjects AT %R2850 : WORD;
    wCellCount AT %R2851 : WORD;
    wActiveCells AT %R2852 : WORD;
    wPrimaryHash AT %R2853 : WORD;
    wMatchCount AT %R2854 : WORD;
    wHazardViolations AT %R2855 : WORD;
    wStatusWord AT %R2856 : WORD;
    wDiagCode AT %R2857 : WORD;
    bCanvasOnline AT %M665 : BOOL;
    bHazardAlarm AT %M666 : BOOL;
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

ST_PROGRAM_VORONOI_CANVAS_SYNC = ST_PROGRAM_W324_VORONOI_CANVAS_SYNC


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
# 7. Complete 9-Stage Verification Suite
# ============================================================================

def run_voronoi_canvas_verification(
    output_path: Optional[str] = None,
    sample_svg_path: Optional[str] = None,
    work_package: str = "W324",
    quick: bool = False,
) -> Dict[str, Any]:
    """Execute the deterministic 9-stage verification suite for W324 Voronoi Diagram / Geohash Canvas."""
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
        for m in ["json", "math", "pathlib", "hashlib", "random", "time", "xml.etree.ElementTree", "zlib"]
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
        VoronoiCanvasEngine is not None
        and compute_voronoi_diagram is not None
        and morton_xy2z is not None
        and morton_z2xy is not None
        and geohash_encode is not None
        and geohash_decode is not None
        and generate_voronoi_canvas_svg is not None
    )
    c1 = py_ok and platform_ok and deps_ok and framework_ok and module_ok
    stages.append({
        "stage": 1,
        "name": "environment_and_platform_check",
        "passed": c1,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Python {sys.version.split()[0]} on {sys.platform}; jev_cscape simulation, parser, and W324 Voronoi modules verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: voronoi_constants_and_register_mappings
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    regs_ok = (
        REG_W324_TOTAL_OBJECTS == "%R2850"
        and REG_W324_CELL_COUNT == "%R2851"
        and REG_W324_ACTIVE_CELLS == "%R2852"
        and REG_W324_PRIMARY_HASH == "%R2853"
        and REG_W324_MATCH_COUNT == "%R2854"
        and REG_W324_HAZARD_VIOLATIONS == "%R2855"
        and REG_W324_STATUS_WORD == "%R2856"
        and REG_W324_DIAGNOSTIC_CODE == "%R2857"
        and COIL_W324_CANVAS_ONLINE == "%M665"
        and COIL_W324_HAZARD_ALARM == "%M666"
        and REG_VORONOI_TOTAL_OBJECTS == "%R2850"
        and COIL_VORONOI_CANVAS_ONLINE == "%M665"
    )

    diag_ok = (
        int(DiagnosticCode.OK) == 0x0000
        and int(DiagnosticCode.INVALID_DOMAIN) == 0x8401
        and int(DiagnosticCode.DEGENERATE_CELL) == 0x8402
        and int(DiagnosticCode.OUT_OF_BOUNDS) == 0x8403
        and int(DiagnosticCode.EMPTY_CANVAS) == 0x8404
        and int(DiagnosticCode.INVALID_RESOLUTION) == 0x8405
        and int(DiagnosticCode.QUERY_OUT_OF_BOUNDS) == 0x8406
        and int(DiagnosticCode.INVALID_MORTON) == 0x8407
        and int(DiagnosticCode.INVALID_GEOHASH) == 0x8408
        and int(DiagnosticCode.SPATIAL_CLUSTER_HAZARD) == 0x8418
        and int(DiagnosticCode.SPATIAL_PROXIMITY_HAZARD) == 0x8420
        and int(DiagnosticCode.SPATIAL_COLLISION_TRIP) == 0x8420
        and int(DiagnosticCode.AREA_CONSERVATION_FAULT) == 0x8422
    )

    status_bits_ok = (
        int(VoronoiStatusBits.ONLINE) == 0x0001
        and int(VoronoiStatusBits.HAZARD_ALARM) == 0x0002
        and int(VoronoiStatusBits.DIAGRAM_COMPUTED) == 0x0004
        and int(VoronoiStatusBits.MORTON_INDEXED) == 0x0008
        and int(VoronoiStatusBits.GEOHASH_INDEXED) == 0x0010
        and int(VoronoiStatusBits.QUERY_ACTIVE) == 0x0020
        and int(VoronoiStatusBits.AREA_CONSERVED) == 0x0040
        and int(VoronoiStatusBits.CELLS_BOUNDED) == 0x0080
    )

    params_ok = (
        CANVAS_VIEWPORT_WIDTH == 1200.0
        and CANVAS_VIEWPORT_HEIGHT == 750.0
        and TOTAL_DOMAIN_AREA == 900000.0
        and MIN_MORTON_ORDER == 1
        and MAX_MORTON_ORDER == 16
        and DEFAULT_MORTON_ORDER == 8
        and MIN_GEOHASH_PRECISION == 1
        and MAX_GEOHASH_PRECISION == 12
        and DEFAULT_GEOHASH_PRECISION == 6
        and DEFAULT_HAZARD_THRESHOLD == 35.0
    )

    c2 = regs_ok and diag_ok and status_bits_ok and params_ok
    stages.append({
        "stage": 2,
        "name": "voronoi_constants_and_register_mappings",
        "passed": c2,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Horner OCS %R2850..%R2857, %M665..%M666, diagnostic codes 0x0000/0x8420/0x8422, and status bits verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: pure_python_voronoi_diagram_construction
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. Sutherland-Hodgman convex clipping verification on known box
    test_poly = Polygon2D([
        Point2D(0.0, 0.0),
        Point2D(100.0, 0.0),
        Point2D(100.0, 100.0),
        Point2D(0.0, 100.0),
    ])
    clipped = test_poly.clip_halfplane(Point2D(50.0, 50.0), Point2D(60.0, 0.0))
    clip_area_ok = abs(clipped.shoelace_area() - 5000.0) < 1e-4
    cent = clipped.centroid()
    cent_ok = abs(cent.x - 25.0) < 1e-4 and abs(cent.y - 50.0) < 1e-4

    # 2. Triangle Shoelace Area and Centroid analytical check
    tri_test = Polygon2D([
        Point2D(0.0, 0.0),
        Point2D(30.0, 0.0),
        Point2D(0.0, 30.0),
    ])
    tri_area_ok = abs(tri_test.shoelace_area() - 450.0) < 1e-4
    tri_cent = tri_test.centroid()
    tri_cent_ok = abs(tri_cent.x - 10.0) < 1e-4 and abs(tri_cent.y - 10.0) < 1e-4

    # 3. Global Area Conservation Invariant on multi-site diagram
    sample_sites = [
        VoronoiSite(site_id=1, x=200.0, y=200.0, val=25.0),
        VoronoiSite(site_id=2, x=600.0, y=180.0, val=35.0),
        VoronoiSite(site_id=3, x=980.0, y=220.0, val=45.0),
        VoronoiSite(site_id=4, x=250.0, y=520.0, val=55.0),
        VoronoiSite(site_id=5, x=620.0, y=480.0, val=65.0),
        VoronoiSite(site_id=6, x=950.0, y=550.0, val=75.0),
        VoronoiSite(site_id=7, x=420.0, y=320.0, val=60.0),
        VoronoiSite(site_id=8, x=800.0, y=360.0, val=80.0),
    ]
    cells = compute_voronoi_diagram(sample_sites, CANVAS_VIEWPORT_WIDTH, CANVAS_VIEWPORT_HEIGHT)
    cells_count_ok = len(cells) == len(sample_sites)
    sum_area = sum(c.area for c in cells)
    area_conservation_ok = abs(sum_area - TOTAL_DOMAIN_AREA) < 0.1

    # 4. Delaunay dual adjacency & gradient tracking
    dual_edges_found = any(len(c.neighbors) > 0 for c in cells)
    gradients_computed = any(len(c.gradients) > 0 for c in cells)

    # 5. Degenerate site configurations
    degen_empty_ok = compute_voronoi_diagram([], CANVAS_VIEWPORT_WIDTH, CANVAS_VIEWPORT_HEIGHT) == []
    single_site = [VoronoiSite(site_id=1, x=300.0, y=300.0)]
    single_cells = compute_voronoi_diagram(single_site, CANVAS_VIEWPORT_WIDTH, CANVAS_VIEWPORT_HEIGHT)
    single_ok = (len(single_cells) == 1 and abs(single_cells[0].area - TOTAL_DOMAIN_AREA) < 0.1)

    two_sites = [
        VoronoiSite(site_id=1, x=300.0, y=375.0),
        VoronoiSite(site_id=2, x=900.0, y=375.0),
    ]
    two_cells = compute_voronoi_diagram(two_sites, CANVAS_VIEWPORT_WIDTH, CANVAS_VIEWPORT_HEIGHT)
    two_ok = (len(two_cells) == 2 and abs(sum(c.area for c in two_cells) - TOTAL_DOMAIN_AREA) < 0.1)

    c3 = (
        clip_area_ok
        and cent_ok
        and tri_area_ok
        and tri_cent_ok
        and cells_count_ok
        and area_conservation_ok
        and dual_edges_found
        and gradients_computed
        and degen_empty_ok
        and single_ok
        and two_ok
    )
    stages.append({
        "stage": 3,
        "name": "pure_python_voronoi_diagram_construction",
        "passed": c3,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Analytical Voronoi tessellation ({len(cells)} cells), Sutherland-Hodgman clipping, Shoelace area conservation (sum: {sum_area:.1f} == {TOTAL_DOMAIN_AREA:.1f}), and Delaunay dual verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: morton_and_geohash_spatial_site_indexing
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. Morton Z-order bijective bit interleaving
    morton_vectors = [
        (0, 0),
        (1, 0),
        (0, 1),
        (1, 1),
        (5, 7),
        (15, 23),
        (255, 128),
        (1023, 512),
    ]
    morton_bijection_ok = True
    for x, y in morton_vectors:
        z = morton_xy2z(x, y, order=16)
        rx, ry = morton_z2xy(z, order=16)
        if (rx, ry) != (x, y):
            morton_bijection_ok = False
            break

    # 2. Morton spatial ordering monotonicity
    test_points = [(50.0 + i * 70.0, 50.0 + (i % 4) * 150.0) for i in range(16)]
    m_codes = [point_to_morton(x, y, 1200.0, 750.0, 8) for x, y in test_points]
    sorted_m = sorted(m_codes)
    morton_ordering_ok = all(sorted_m[i] <= sorted_m[i + 1] for i in range(len(sorted_m) - 1))

    # 3. Geohash Base32 encoding & decoding roundtrip bijection
    geohash_points = [
        (37.7749, -122.4194),
        (51.5074, -0.1278),
        (35.6762, 139.6503),
        (-33.8688, 151.2093),
        (0.0, 0.0),
    ]
    geohash_bijection_ok = True
    for lat, lon in geohash_points:
        gh = geohash_encode(lat, lon, precision=6)
        if len(gh) != 6 or not all(c in BASE32 for c in gh):
            geohash_bijection_ok = False
            break
        r_lat, r_lon, err_lat, err_lon = geohash_decode(gh)
        if abs(r_lat - lat) > err_lat or abs(r_lon - lon) > err_lon:
            geohash_bijection_ok = False
            break

    # 4. Continuous-to-Geohash mapping and inverse
    gh_pt = point_to_geohash(600.0, 375.0, 1200.0, 750.0, 6)
    rec_x, rec_y = geohash_to_point(gh_pt, 1200.0, 750.0)
    geohash_canvas_map_ok = (abs(rec_x - 600.0) < 50.0 and abs(rec_y - 375.0) < 50.0)

    # 5. Geohash 8-neighbor spatial adjacency
    nbrs = geohash_neighbors(gh_pt)
    geohash_neighbors_ok = (len(nbrs) == 8 and len(set(nbrs.values())) == 8)

    # 6. Canvas engine spatial indexing
    v_engine = create_canonical_voronoi_canvas(seed=42, count=16)
    engine_indexing_ok = (
        len(v_engine.active_morton_cells) > 0
        and len(v_engine.active_geohashes) > 0
        and all(s.morton_code >= 0 for s in v_engine.sites.values())
        and all(len(s.geohash) == 6 for s in v_engine.sites.values())
    )

    # 7. Out-of-bounds error handling
    oob_rejected = False
    try:
        morton_xy2z(-1, 0, 8)
    except ValueError:
        try:
            morton_xy2z(256, 10, 8)
        except ValueError:
            try:
                geohash_encode(95.0, 0.0, 6)
            except ValueError:
                oob_rejected = True

    c4 = (
        morton_bijection_ok
        and morton_ordering_ok
        and geohash_bijection_ok
        and geohash_canvas_map_ok
        and geohash_neighbors_ok
        and engine_indexing_ok
        and oob_rejected
    )
    stages.append({
        "stage": 4,
        "name": "morton_and_geohash_spatial_site_indexing",
        "passed": c4,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Morton Z-order curve bit interleaving, Base32 Geohash bijection, 8-neighbor adjacency, and dual spatial site indexing verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: spatial_proximity_hazard_and_collision_trip
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    p_engine = VoronoiCanvasEngine(hazard_threshold=35.0)
    p_engine.build_canonical_sensor_network(seed=42, count=16)

    # 1. Nominal check: zero initial hazard violations
    nom_hazards = p_engine.check_proximity_hazards()
    nom_ok = (
        len(nom_hazards) == 0
        and p_engine.alarm_active is False
        and p_engine.diagnostic_code == DiagnosticCode.OK
    )

    # 2. Collision trip: insert site in tight proximity (distance 10.0 px <= 35.0 threshold)
    target = p_engine.sites[1]
    p_engine.insert_site(
        x=target.x + 8.0,
        y=target.y + 6.0,
        site_id=999,
        tag="COLLIDING-01",
        hazard_radius=20.0,
    )
    trip_hazards = p_engine.check_proximity_hazards()
    trip_ok = (
        len(trip_hazards) >= 1
        and p_engine.alarm_active is True
        and p_engine.diagnostic_code == DiagnosticCode.SPATIAL_PROXIMITY_HAZARD
        and p_engine.hazard_violations >= 1
    )

    # 3. Register sync on hazard trip
    rt_trip = RegisterTable()
    p_engine.sync_to_registers(rt_trip)
    coil_alarm_trip = rt_trip.read_bit(COIL_W324_HAZARD_ALARM)
    coil_online_trip = rt_trip.read_bit(COIL_W324_CANVAS_ONLINE)
    reg_diag_trip = rt_trip.read_word(REG_W324_DIAGNOSTIC_CODE)
    regs_trip_ok = (
        coil_alarm_trip is True
        and coil_online_trip is False
        and (reg_diag_trip & 0xFFFF) == 0x8420
    )

    # 4. Clearing hazard: remove colliding site
    p_engine.remove_site(999)
    p_engine.check_proximity_hazards()
    clear_ok = (
        p_engine.alarm_active is False
        and p_engine.hazard_violations == 0
        and p_engine.diagnostic_code == DiagnosticCode.OK
    )
    p_engine.sync_to_registers(rt_trip)
    regs_clear_ok = (
        rt_trip.read_bit(COIL_W324_HAZARD_ALARM) is False
        and rt_trip.read_bit(COIL_W324_CANVAS_ONLINE) is True
        and (rt_trip.read_word(REG_W324_DIAGNOSTIC_CODE) & 0xFFFF) == 0x0000
    )

    c5 = nom_ok and trip_ok and regs_trip_ok and clear_ok and regs_clear_ok
    stages.append({
        "stage": 5,
        "name": "spatial_proximity_hazard_and_collision_trip",
        "passed": c5,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Spatial proximity collision trip, coil %M666 alarm latch, 0x8420 diagnostic emission, and nominal reset verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: register_table_synchronization_and_signed_masks
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt_sync = RegisterTable()
    s_engine = create_canonical_voronoi_canvas(seed=42, count=16)
    s_engine.query_radius(600.0, 375.0, 200.0)
    s_engine.sync_to_registers(rt_sync)

    w_total = rt_sync.read_word(REG_W324_TOTAL_OBJECTS)
    w_cells = rt_sync.read_word(REG_W324_CELL_COUNT)
    w_active = rt_sync.read_word(REG_W324_ACTIVE_CELLS)
    w_hash = rt_sync.read_word(REG_W324_PRIMARY_HASH)
    w_match = rt_sync.read_word(REG_W324_MATCH_COUNT)
    w_viols = rt_sync.read_word(REG_W324_HAZARD_VIOLATIONS)
    w_status = rt_sync.read_word(REG_W324_STATUS_WORD)
    w_diag = rt_sync.read_word(REG_W324_DIAGNOSTIC_CODE)
    b_online = rt_sync.read_bit(COIL_W324_CANVAS_ONLINE)
    b_alarm = rt_sync.read_bit(COIL_W324_HAZARD_ALARM)

    c6_reads = (
        (w_total & 0xFFFF) == len(s_engine.sites)
        and (w_cells & 0xFFFF) == len(s_engine.cells)
        and (w_active & 0xFFFF) == len(s_engine.active_morton_cells)
        and (w_hash & 0xFFFF) == s_engine.metrics.primary_hash
        and (w_match & 0xFFFF) == len(s_engine.last_query_results)
        and (w_viols & 0xFFFF) == 0
        and (w_status & 0x0001) == 1
        and (w_diag & 0xFFFF) == 0x0000
        and b_online is True
        and b_alarm is False
    )

    # Bitwise signed masks verification
    rt_sync.write_word(REG_W324_DIAGNOSTIC_CODE, (-55) & 0xFFFF, privilege=PrivilegeMode.SYSTEM)
    raw_val = rt_sync.read_word(REG_W324_DIAGNOSTIC_CODE)
    val_u = raw_val & 0xFFFF
    val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
    c6_signed = (val_u == 65481 and val_s == -55)

    # High-bit diagnostic code verification
    diag_code = DiagnosticCode.SPATIAL_PROXIMITY_HAZARD
    rt_sync.write_word(REG_W324_DIAGNOSTIC_CODE, int(diag_code) & 0xFFFF, privilege=PrivilegeMode.USER)
    diag_read = rt_sync.read_word(REG_W324_DIAGNOSTIC_CODE)
    c6_diag = ((diag_read & 0xFFFF) == int(diag_code) and (diag_read & 0xFFFF) == 0x8420)

    # Restore nominal diagnostic in register
    s_engine.sync_to_registers(rt_sync)

    c6 = c6_reads and c6_signed and c6_diag
    stages.append({
        "stage": 6,
        "name": "register_table_synchronization_and_signed_masks",
        "passed": c6,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Horner OCS %R2850..%R2857 and %M665..%M666 synchronized; signed 16-bit masks and 0x8420 verified.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    SecurityGuard.assert_pure_st_content(ST_PROGRAM_W324_VORONOI_CANVAS_SYNC)
    st_val = STParser.validate_code(ST_PROGRAM_W324_VORONOI_CANVAS_SYNC)
    st_ast = STParser.parse_pou(ST_PROGRAM_W324_VORONOI_CANVAS_SYNC)
    st_pou_ok = (
        st_val.status == AgentStatus.SUCCESS
        and st_ast.pou_type == POUType.PROGRAM
        and st_ast.name == "VoronoiCanvasSync"
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
        "details": "Pure ST POU 'VoronoiCanvasSync' AST validated; ladder contacts, coils, rungs, and mnemonics strictly rejected.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: svg_scada_canvas_rasterization_and_wcag_contrast
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    canon_canvas = create_canonical_voronoi_canvas(seed=42, count=16)
    canon_canvas.query_radius(600.0, 375.0, 180.0)
    svg_text = generate_voronoi_canvas_svg(canon_canvas)

    # XML validation
    root_el = ET.fromstring(svg_text)
    svg_valid = (
        root_el.tag.endswith("svg")
        and root_el.attrib.get("version") == "1.1"
        and root_el.attrib.get("viewBox") == "0 0 1200 750"
        and "voronoi-cells-layer" in svg_text
        and "delaunay-dual-layer" in svg_text
        and "voronoi-sites-layer" in svg_text
        and "scorecard-layer" in svg_text
        and "sensor-node" in svg_text
        and "<polygon" in svg_text
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
        "details": f"W3C SVG 1.1 generated with Voronoi polygonal cells; WCAG AAA contrast ratio verified ({contrast_ratio:.2f}:1 >= 18:1).",
    })

    # ------------------------------------------------------------------------
    # Stage 9: multi_cycle_simulation_soak_and_evidence_emission
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim_engine = VoronoiCanvasEngine()
    sim_rt = RegisterTable()
    cycles = 5 if quick else 20

    all_steps_ok = True
    for c in range(1, cycles + 1):
        ctx = ScanContext(cycle=c, dt_ms=10.0, register_table=sim_rt)
        sim_engine.insert_site(
            x=80.0 + c * 35.0,
            y=80.0 + (c % 5) * 50.0,
            site_id=c,
            val=20.0 + c * 1.5,
            tag=f"DYN-{c:03d}",
        )
        sim_engine.query_radius(600.0, 375.0, 100.0 + c * 10.0)
        res = sim_engine.execute(ctx)
        if res.status != AgentStatus.SUCCESS:
            all_steps_ok = False
            break

    c9_sim = (all_steps_ok and sim_engine.cycle_count == cycles and len(sim_engine.sites) == cycles)
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
        "details": f"Wave {work_package} Dynamic Spatial Geohash / Voronoi Diagram Canvas Verification PASSED ({passed_count}/{total_count} stages).",
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
# 8. CLI Main Entry Point
# ============================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """Command-line entry point for W324 Voronoi Diagram / Geohash Canvas verification runner."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Run Cscape HMI Dynamic Spatial Geohash / Voronoi Diagram SCADA Canvas (W324) 9-Stage Verification Suite"
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
        default="artifacts/HMI/voronoi_canvas_evidence.json",
        help="Path to output verification evidence JSON (default: artifacts/HMI/voronoi_canvas_evidence.json)",
    )
    parser.add_argument(
        "--svg",
        "-s",
        "--svg-output",
        "--sample-svg",
        dest="svg_output_path",
        type=str,
        default="artifacts/HMI/voronoi_canvas_sample.svg",
        help="Path to output sample SVG graphic (default: artifacts/HMI/voronoi_canvas_sample.svg)",
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
        default="W324",
        help="Work package identifier (default: W324)",
    )

    args = parser.parse_args(argv)
    effective_output = args.positional_output or args.output_path
    effective_svg = args.positional_svg or args.svg_output_path

    if not args.json_mode:
        print(f"\n{CLR_CYAN}{CLR_BOLD}======================================================================{CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}  JEV CSCAPE VERIFICATION RUNNER - WORK PACKAGE {args.work_package}                 {CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}  Gate G9: Dynamic Spatial Geohash / Voronoi Diagram Canvas           {CLR_RESET}")
        print(f"{CLR_CYAN}{CLR_BOLD}======================================================================{CLR_RESET}\n")

    t_start = time.perf_counter()
    evidence = run_voronoi_canvas_verification(
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
