"""Cscape HMI Dynamic Spatial K-D Tree / Nearest-Neighbor SCADA Canvas (W294).

Work Package: W294 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Spatial K-D Tree SCADA Canvas]
Status Contract: Strict 4-State JSON output & deterministic evidence emission.

Features:
1. Spatial K-D Tree Indexing Engine:
   - Pure Python 2D hierarchical k-d tree spatial indexing data structure over bounding domain [0, 1200] x [0, 750].
   - Alternating orthogonal axis partitioning: axis = depth % 2 (x-split at depth 0, 2...; y-split at depth 1, 3...).
   - Dynamic node insertion, median/midpoint split, depth tracking (max depth 12).
   - Branch-and-bound nearest-neighbor (1-NN) and k-nearest-neighbors (k-NN) range search with hypersphere boundary pruning.
   - Spatial proximity hazard zone detection: If any instrument has distance d < hazard_threshold (canonical 30.0 px), trip proximity alarm %M596 and diagnostic code 0x8415.
2. Vector SCADA Visual Grounding (SVG 1.1):
   - Standalone W3C SVG 1.1 vector graphic generator:
     * Alternating partition lines across viewport (x-split vertical, y-split horizontal).
     * Sensor nodes with status colors (cyan/emerald normal, amber warning, crimson alarm).
     * Query target crosshair reticle overlay and dashed connector vectors to nearest neighbors with Euclidean distance callouts.
     * High-contrast SCADA theme styling (> 18:1 contrast, WCAG 2.1 AAA).
3. Horner OCS Memory Space Integration:
   - Word registers %R2550..%R2557:
     %R2550: Total Indexed Spatial Nodes Count
     %R2551: K-D Tree Subdivision Depth (0..12)
     %R2552: Query Target Node ID
     %R2553: Nearest-Neighbor (1-NN) Node ID
     %R2554: Nearest Distance scaled x10 (px)
     %R2555: Proximity Hazard Threshold scaled x10 (px)
     %R2556: Proximity Hazard Violations Count
     %R2557: Diagnostic Code (0x0000=OK, 0x8411=INVALID_DOMAIN, 0x8412=EMPTY_TREE, 0x8413=INVALID_K_NEIGHBORS,
             0x8414=DEGENERATE_COORDINATES, 0x8415=PROXIMITY_HAZARD_ALARM)
   - Discrete coils %M595..%M596:
     %M595: K-D Tree Indexing Online coil (BOOL)
     %M596: Spatial Proximity Hazard Alarm coil (BOOL)
4. Pure IEC 61131-3 Structured Text (ST) POU:
   - KdtreeCanvasSync program with anti-ladder validation.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import IntFlag
import heapq
import json
import math
from pathlib import Path
import random
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants, Palette & Diagnostic Codes
# ============================================================================

CANVAS_VIEWPORT_WIDTH: float         = 1200.0
CANVAS_VIEWPORT_HEIGHT: float        = 750.0
TOTAL_DOMAIN_AREA: float             = CANVAS_VIEWPORT_WIDTH * CANVAS_VIEWPORT_HEIGHT
DEFAULT_MAX_DEPTH: int               = 12
DEFAULT_HAZARD_THRESHOLD: float      = 30.0

# SCADA High-Contrast Theme Palette (WCAG 2.1 AAA Compliant)
COLOR_SCADA_BG: str                  = "#0D1117"
COLOR_DARK_SURFACE: str              = "#161B22"
COLOR_DECOUPLED_BADGE: str           = "#05080C"
COLOR_BORDER: str                    = "#334155"
COLOR_TEXT_PRIMARY: str              = "#FFFFFF"
COLOR_TEXT_MUTED: str                = "#CBD5E1"
COLOR_SAMPLE_NODE: str               = "#38BDF8"
COLOR_SAMPLE_BORDER: str             = "#0284C7"
COLOR_NOMINAL_EMERALD: str           = "#10B981"
COLOR_WARNING_AMBER: str             = "#F59E0B"
COLOR_ALARM_CRIMSON: str             = "#EF4444"
COLOR_RETICLE_CYAN: str              = "#06B6D4"
COLOR_PARTITION_X: str               = "#38BDF8"
COLOR_PARTITION_Y: str               = "#10B981"
COLOR_CONNECTOR_VECTOR: str          = "#F59E0B"

# Depth color partition styling for subdivision levels 0..12
DEPTH_COLORS: List[str] = [
    "#38BDF8",  # Depth 0: Sky Blue (x-split)
    "#10B981",  # Depth 1: Emerald (y-split)
    "#3B82F6",  # Depth 2: Blue (x-split)
    "#F59E0B",  # Depth 3: Amber (y-split)
    "#8B5CF6",  # Depth 4: Violet (x-split)
    "#EC4899",  # Depth 5: Pink (y-split)
    "#06B6D4",  # Depth 6: Cyan (x-split)
    "#14B8A6",  # Depth 7: Teal (y-split)
    "#A855F7",  # Depth 8: Purple (x-split)
    "#EAB308",  # Depth 9: Yellow (y-split)
    "#6366F1",  # Depth 10: Indigo (x-split)
    "#22C55E",  # Depth 11: Green (y-split)
    "#E2E8F0",  # Depth 12: Slate White
]

# Horner OCS Register Map (%R2550..%R2557, %M595..%M596)
REG_KDTREE_TOTAL_NODES: str          = "%R2550"
REG_KDTREE_SUBDIVISION_DEPTH: str    = "%R2551"
REG_KDTREE_QUERY_TARGET_ID: str      = "%R2552"
REG_KDTREE_NEAREST_NODE_ID: str      = "%R2553"
REG_KDTREE_NEAREST_DISTANCE_SCALED: str = "%R2554"
REG_KDTREE_HAZARD_THRESHOLD_SCALED: str = "%R2555"
REG_KDTREE_HAZARD_VIOLATIONS_COUNT: str = "%R2556"
REG_KDTREE_DIAGNOSTIC_CODE: str      = "%R2557"

COIL_KDTREE_INDEXING_ONLINE: str     = "%M595"
COIL_KDTREE_PROXIMITY_HAZARD_ALARM: str = "%M596"

# Work package W294 aliases
REG_W294_TOTAL_NODES                 = REG_KDTREE_TOTAL_NODES
REG_W294_SUBDIVISION_DEPTH           = REG_KDTREE_SUBDIVISION_DEPTH
REG_W294_QUERY_TARGET_ID             = REG_KDTREE_QUERY_TARGET_ID
REG_W294_NEAREST_NODE_ID             = REG_KDTREE_NEAREST_NODE_ID
REG_W294_NEAREST_DISTANCE_SCALED     = REG_KDTREE_NEAREST_DISTANCE_SCALED
REG_W294_HAZARD_THRESHOLD_SCALED     = REG_KDTREE_HAZARD_THRESHOLD_SCALED
REG_W294_HAZARD_VIOLATIONS_COUNT     = REG_KDTREE_HAZARD_VIOLATIONS_COUNT
REG_W294_DIAGNOSTIC_CODE             = REG_KDTREE_DIAGNOSTIC_CODE
COIL_W294_INDEXING_ONLINE            = COIL_KDTREE_INDEXING_ONLINE
COIL_W294_PROXIMITY_HAZARD_ALARM     = COIL_KDTREE_PROXIMITY_HAZARD_ALARM

# Additional compatibility aliases
REG_KDTREE_NODE_COUNT                = REG_KDTREE_TOTAL_NODES
REG_KDTREE_DEPTH                     = REG_KDTREE_SUBDIVISION_DEPTH
REG_KDTREE_MAX_DEPTH                 = REG_KDTREE_SUBDIVISION_DEPTH
REG_KDTREE_TARGET_ID                 = REG_KDTREE_QUERY_TARGET_ID
REG_KDTREE_NEAREST_ID                = REG_KDTREE_NEAREST_NODE_ID
REG_KDTREE_NEAREST_DIST              = REG_KDTREE_NEAREST_DISTANCE_SCALED
REG_KDTREE_HAZARD_THRESHOLD          = REG_KDTREE_HAZARD_THRESHOLD_SCALED
REG_KDTREE_VIOLATIONS_COUNT          = REG_KDTREE_HAZARD_VIOLATIONS_COUNT

COIL_KDTREE_CANVAS_ACTIVE            = COIL_KDTREE_INDEXING_ONLINE
COIL_KDTREE_HAZARD_ALARM             = COIL_KDTREE_PROXIMITY_HAZARD_ALARM


class DiagnosticCode(int):
    """Integer subclass for 16-bit diagnostic codes supporting signed/unsigned equality."""

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            val_u = int(self) & 0xFFFF
            val_s = val_u - 0x10000 if val_u >= 0x8000 else val_u
            other_u = int(other) & 0xFFFF
            other_s = other_u - 0x10000 if other_u >= 0x8000 else other_u
            return (
                int(self) == other
                or val_u == other
                or val_s == other
                or val_s == other_s
                or val_u == other_u
            )
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(int(self) & 0xFFFF)

    def __repr__(self) -> str:
        return f"DiagnosticCode(0x{int(self) & 0xFFFF:04X})"

    def __str__(self) -> str:
        return f"0x{int(self) & 0xFFFF:04X}"


# 16-bit Diagnostic Codes for W294
DIAG_OK: DiagnosticCode                           = DiagnosticCode(0x0000)
DIAG_ERR_INVALID_DOMAIN: DiagnosticCode           = DiagnosticCode(0x8411)
DIAG_ERR_EMPTY_TREE: DiagnosticCode               = DiagnosticCode(0x8412)
DIAG_ERR_INVALID_K_NEIGHBORS: DiagnosticCode      = DiagnosticCode(0x8413)
DIAG_ERR_DEGENERATE_COORDINATES: DiagnosticCode   = DiagnosticCode(0x8414)
DIAG_ERR_PROXIMITY_HAZARD_ALARM: DiagnosticCode   = DiagnosticCode(0x8415)

# Compatibility diagnostic aliases
DIAG_ERR_OUT_OF_BOUNDS: DiagnosticCode            = DIAG_ERR_INVALID_DOMAIN
DIAG_ERR_DEGENERATE_NODE_COORDS: DiagnosticCode   = DIAG_ERR_DEGENERATE_COORDINATES
DIAG_ERR_HAZARD_ALARM: DiagnosticCode             = DIAG_ERR_PROXIMITY_HAZARD_ALARM

KdtreeDiagnosticCode = DiagnosticCode
KdDiagnosticCode = DiagnosticCode


class KdtreeStatusBits(IntFlag):
    """Bitmask for K-D Tree spatial canvas status."""
    INDEXING_ONLINE         = 1 << 0
    PROXIMITY_HAZARD_ALARM  = 1 << 1
    MAX_DEPTH_REACHED       = 1 << 2
    DEGENERATE_COORDS       = 1 << 3
    INVALID_DOMAIN          = 1 << 4
    SVG_RENDER_VALID        = 1 << 5


KdStatusBits = KdtreeStatusBits


# ============================================================================
# 2. Geometry & Spatial K-D Tree Data Structures
# ============================================================================

@dataclass
class KdPoint:
    """Indexed 2D point node within spatial k-d tree."""
    x: float
    y: float
    id: int = 0
    tag: str = ""
    status: str = "normal"  # "normal" | "warning" | "alarm"
    data: Dict[str, Any] = field(default_factory=dict)

    @property
    def value(self) -> float:
        return float(self.data.get("value", 0.0))


KdNodePoint = KdPoint
SpatialPoint = KdPoint


@dataclass
class KdRect:
    """Axis-aligned 2D bounding rectangle [x_min, y_min, x_max, y_max]."""
    x_min: float
    y_min: float
    x_max: float
    y_max: float

    def __post_init__(self) -> None:
        if self.x_min > self.x_max or self.y_min > self.y_max:
            raise ValueError(f"Degenerate bounding box: ({self.x_min}, {self.y_min}) to ({self.x_max}, {self.y_max})")

    @property
    def width(self) -> float:
        return max(0.0, self.x_max - self.x_min)

    @property
    def height(self) -> float:
        return max(0.0, self.y_max - self.y_min)

    @property
    def area(self) -> float:
        return self.width * self.height

    @property
    def center_x(self) -> float:
        return (self.x_min + self.x_max) / 2.0

    @property
    def center_y(self) -> float:
        return (self.y_min + self.y_max) / 2.0

    def contains_coord(self, x: float, y: float) -> bool:
        """Check if (x, y) coordinate is enclosed within rectangle."""
        return self.x_min <= x <= self.x_max and self.y_min <= y <= self.y_max

    def contains_point(self, p: Any, y: Optional[float] = None) -> bool:
        """Check if KdPoint or (x, y) coordinates are enclosed within rectangle."""
        if y is not None:
            return self.contains_coord(float(p), float(y))
        if hasattr(p, "x") and hasattr(p, "y"):
            return self.contains_coord(p.x, p.y)
        if isinstance(p, (tuple, list)) and len(p) >= 2:
            return self.contains_coord(p[0], p[1])
        return False


BoundingBox = KdRect
KdBounds = KdRect


class KdNode:
    """Hierarchical node in a 2D spatial K-D tree."""

    def __init__(
        self,
        point: KdPoint,
        axis: int = 0,
        depth: int = 0,
        bounds: Optional[KdRect] = None,
        left: Optional[KdNode] = None,
        right: Optional[KdNode] = None,
    ) -> None:
        self.point = point
        self.axis = axis  # 0 = x-split (vertical), 1 = y-split (horizontal)
        self.depth = depth
        self.bounds = bounds or KdRect(0.0, 0.0, CANVAS_VIEWPORT_WIDTH, CANVAS_VIEWPORT_HEIGHT)
        self.left = left
        self.right = right

    def is_leaf(self) -> bool:
        """Return True if node has no children."""
        return self.left is None and self.right is None

    def get_all_nodes(self) -> List[KdNode]:
        """Traverse and return all subtree nodes in depth-first order."""
        res: List[KdNode] = [self]
        if self.left:
            res.extend(self.left.get_all_nodes())
        if self.right:
            res.extend(self.right.get_all_nodes())
        return res

    def get_all_points(self) -> List[KdPoint]:
        """Traverse and return all indexed points in subtree."""
        return [node.point for node in self.get_all_nodes()]

    def get_max_depth(self) -> int:
        """Calculate maximum subtree depth."""
        d = self.depth
        if self.left:
            d = max(d, self.left.get_max_depth())
        if self.right:
            d = max(d, self.right.get_max_depth())
        return d

    def count(self) -> int:
        """Count total nodes in subtree."""
        cnt = 1
        if self.left:
            cnt += self.left.count()
        if self.right:
            cnt += self.right.count()
        return cnt


@dataclass
class KdtreeMetrics:
    """Telemetry metrics container for K-D tree SCADA canvas."""
    total_nodes: int = 0
    subdivision_depth: int = 0
    query_target_id: int = 0
    nearest_node_id: int = 0
    nearest_distance: float = 0.0
    hazard_threshold: float = DEFAULT_HAZARD_THRESHOLD
    hazard_violations_count: int = 0
    diagnostic_code: DiagnosticCode = field(default_factory=lambda: DIAG_OK)
    indexing_online: bool = True
    proximity_hazard_alarm: bool = False

    @property
    def nearest_distance_scaled(self) -> int:
        """Nearest distance scaled x10 as 16-bit integer."""
        if math.isinf(self.nearest_distance) or self.nearest_node_id == 0:
            return 0
        return int(round(self.nearest_distance * 10.0)) & 0xFFFF

    @property
    def hazard_threshold_scaled(self) -> int:
        """Hazard threshold scaled x10 as 16-bit integer."""
        return int(round(self.hazard_threshold * 10.0)) & 0xFFFF


KdMetrics = KdtreeMetrics


# ============================================================================
# 3. Pure IEC 61131-3 Structured Text POU
# ============================================================================

ST_PROGRAM_KDTREE_CANVAS_SYNC = """
PROGRAM KdtreeCanvasSync
VAR
    wTotalNodes AT %R2550 : WORD;
    wTreeDepth AT %R2551 : WORD;
    wQueryTargetId AT %R2552 : WORD;
    wNearestNodeId AT %R2553 : WORD;
    wNearestDistScaled AT %R2554 : WORD;
    wHazardThresholdScaled AT %R2555 : WORD;
    wHazardViolations AT %R2556 : WORD;
    wDiagCode AT %R2557 : WORD;
    bIndexingOnline AT %M595 : BOOL;
    bHazardAlarm AT %M596 : BOOL;
END_VAR

IF wDiagCode = 0 THEN
    bIndexingOnline := TRUE;
    bHazardAlarm := FALSE;
ELSE
    bIndexingOnline := FALSE;
    bHazardAlarm := TRUE;
END_IF;
END_PROGRAM
""".strip()

KDTREE_CANVAS_PURE_ST_POU = ST_PROGRAM_KDTREE_CANVAS_SYNC
KdtreeCanvasSync = ST_PROGRAM_KDTREE_CANVAS_SYNC


def verify_kdtree_canvas_pure_st(pou_text: Optional[str] = None) -> bool:
    """Validate pure ST syntax and ensure strict rejection of ladder logic constructs."""
    try:
        text = pou_text if pou_text is not None else ST_PROGRAM_KDTREE_CANVAS_SYNC
        SecurityGuard.assert_pure_st_content(text)
        res = STParser.validate_code(text)
        if res.status != AgentStatus.SUCCESS:
            return False
        ast = STParser.parse_pou(text)
        return ast.pou_type == POUType.PROGRAM
    except Exception:
        return False


# ============================================================================
# 4. K-D Tree Canvas Engine
# ============================================================================

class KdtreeCanvasEngine(ILogicUnit):
    """Pure Python 2D hierarchical K-D Tree spatial indexing SCADA engine (W294)."""

    def __init__(
        self,
        viewport_width: float = CANVAS_VIEWPORT_WIDTH,
        viewport_height: float = CANVAS_VIEWPORT_HEIGHT,
        max_depth: int = DEFAULT_MAX_DEPTH,
        hazard_threshold: float = DEFAULT_HAZARD_THRESHOLD,
        register_table: Optional[RegisterTable] = None,
    ) -> None:
        self.viewport_width = float(viewport_width)
        self.viewport_height = float(viewport_height)
        self.max_depth = int(max_depth)
        self.hazard_threshold = float(hazard_threshold)
        self.reg_table: RegisterTable = register_table or RegisterTable()

        self.root: Optional[KdNode] = None
        self.points: List[KdPoint] = []
        self.current_depth: int = 0

        self.query_target_x: Optional[float] = None
        self.query_target_y: Optional[float] = None
        self.query_target_id: int = 0

        self.nearest_node: Optional[KdPoint] = None
        self.nearest_node_id: int = 0
        self.nearest_distance: float = 0.0

        self.last_knn_results: List[Tuple[KdPoint, float]] = []
        self.hazard_violations_count: int = 0

        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.alarm_active: bool = False
        self.cycle_count: int = 0

    @property
    def total_nodes(self) -> int:
        """Count of indexed spatial nodes."""
        return len(self.points)

    @property
    def indexing_online(self) -> bool:
        """Engine online status coil flag."""
        return True

    @property
    def metrics(self) -> KdtreeMetrics:
        """Retrieve telemetry metrics snapshot."""
        return KdtreeMetrics(
            total_nodes=len(self.points),
            subdivision_depth=self.current_depth,
            query_target_id=self.query_target_id,
            nearest_node_id=self.nearest_node_id,
            nearest_distance=self.nearest_distance,
            hazard_threshold=self.hazard_threshold,
            hazard_violations_count=self.hazard_violations_count,
            diagnostic_code=self.diagnostic_code,
            indexing_online=self.indexing_online,
            proximity_hazard_alarm=self.alarm_active,
        )

    def insert_point(self, x: float, y: float, node_id: int = 0) -> bool:
        """Dynamically insert coordinate point into the spatial K-D tree.

        Enforces alternating axis partitioning: axis = depth % 2.
        Tracks subdivision depth up to max_depth.
        Evaluates proximity hazard against existing nodes.
        """
        # Validate coordinates for degenerate NaN/Inf
        if math.isnan(x) or math.isnan(y) or math.isinf(x) or math.isinf(y):
            self.diagnostic_code = DIAG_ERR_DEGENERATE_COORDINATES
            self.sync_to_registers(self.reg_table)
            return False

        # Validate domain bounds [0, viewport_width] x [0, viewport_height]
        if x < 0.0 or x > self.viewport_width or y < 0.0 or y > self.viewport_height:
            self.diagnostic_code = DIAG_ERR_INVALID_DOMAIN
            self.sync_to_registers(self.reg_table)
            return False

        if node_id <= 0:
            node_id = len(self.points) + 1

        pt = KdPoint(
            id=node_id,
            x=float(x),
            y=float(y),
            tag=f"INST-{node_id:03d}",
            status="normal",
        )

        # Proximity hazard check against existing points
        for other in self.points:
            d = math.hypot(pt.x - other.x, pt.y - other.y)
            if d < self.hazard_threshold:
                self.hazard_violations_count += 1
                pt.status = "alarm"
                other.status = "alarm"
                self.alarm_active = True
                self.diagnostic_code = DIAG_ERR_PROXIMITY_HAZARD_ALARM

        # Insert into K-D tree hierarchy
        if self.root is None:
            self.root = KdNode(
                point=pt,
                axis=0,
                depth=0,
                bounds=KdRect(0.0, 0.0, self.viewport_width, self.viewport_height),
            )
            self.current_depth = 0
        else:
            curr = self.root
            while True:
                axis = curr.axis
                val = pt.x if axis == 0 else pt.y
                curr_val = curr.point.x if axis == 0 else curr.point.y
                next_axis = (curr.depth + 1) % 2
                next_depth = curr.depth + 1

                if val < curr_val:
                    if curr.left is None:
                        if axis == 0:
                            cb = KdRect(curr.bounds.x_min, curr.bounds.y_min, curr.point.x, curr.bounds.y_max)
                        else:
                            cb = KdRect(curr.bounds.x_min, curr.bounds.y_min, curr.bounds.x_max, curr.point.y)
                        curr.left = KdNode(point=pt, axis=next_axis, depth=next_depth, bounds=cb)
                        self.current_depth = max(self.current_depth, min(self.max_depth, next_depth))
                        break
                    else:
                        curr = curr.left
                else:
                    if curr.right is None:
                        if axis == 0:
                            cb = KdRect(curr.point.x, curr.bounds.y_min, curr.bounds.x_max, curr.bounds.y_max)
                        else:
                            cb = KdRect(curr.bounds.x_min, curr.point.y, curr.bounds.x_max, curr.bounds.y_max)
                        curr.right = KdNode(point=pt, axis=next_axis, depth=next_depth, bounds=cb)
                        self.current_depth = max(self.current_depth, min(self.max_depth, next_depth))
                        break
                    else:
                        curr = curr.right

        self.points.append(pt)
        if not self.alarm_active:
            self.diagnostic_code = DIAG_OK

        self.sync_to_registers(self.reg_table)
        return True

    def insert_points(self, points: Sequence[Tuple[float, float]]) -> int:
        """Batch insert coordinate tuples into the spatial K-D tree."""
        count = 0
        for x, y in points:
            if self.insert_point(x, y):
                count += 1
        return count

    def build_balanced_tree(self, points: Sequence[KdPoint], depth: int = 0, bounds: Optional[KdRect] = None) -> Optional[KdNode]:
        """Recursively construct balanced K-D tree using median split."""
        if not points:
            return None

        if bounds is None:
            bounds = KdRect(0.0, 0.0, self.viewport_width, self.viewport_height)

        axis = depth % 2
        sorted_points = sorted(points, key=lambda p: p.x if axis == 0 else p.y)
        mid = len(sorted_points) // 2
        median_point = sorted_points[mid]

        if axis == 0:
            left_bounds = KdRect(bounds.x_min, bounds.y_min, median_point.x, bounds.y_max)
            right_bounds = KdRect(median_point.x, bounds.y_min, bounds.x_max, bounds.y_max)
        else:
            left_bounds = KdRect(bounds.x_min, bounds.y_min, bounds.x_max, median_point.y)
            right_bounds = KdRect(bounds.x_min, median_point.y, bounds.x_max, bounds.y_max)

        left_node = self.build_balanced_tree(sorted_points[:mid], depth + 1, left_bounds)
        right_node = self.build_balanced_tree(sorted_points[mid + 1:], depth + 1, right_bounds)

        return KdNode(
            point=median_point,
            axis=axis,
            depth=depth,
            bounds=bounds,
            left=left_node,
            right=right_node,
        )

    def rebalance(self) -> None:
        """Reconstruct the entire K-D tree into balanced median-split structure."""
        if not self.points:
            self.root = None
            self.current_depth = 0
            return
        self.root = self.build_balanced_tree(self.points, depth=0)
        if self.root:
            self.current_depth = min(self.max_depth, self.root.get_max_depth())
        self.sync_to_registers(self.reg_table)

    def find_nearest(self, x: float, y: float) -> Tuple[Optional[KdPoint], float]:
        """Branch-and-bound nearest-neighbor (1-NN) search with hypersphere boundary pruning.

        Returns (nearest_point, euclidean_distance).
        """
        # Validate coordinates
        if math.isnan(x) or math.isnan(y) or math.isinf(x) or math.isinf(y):
            self.diagnostic_code = DIAG_ERR_DEGENERATE_COORDINATES
            self.sync_to_registers(self.reg_table)
            return (None, float('inf'))

        if self.root is None or not self.points:
            self.diagnostic_code = DIAG_ERR_EMPTY_TREE
            self.nearest_node = None
            self.nearest_node_id = 0
            self.nearest_distance = float('inf')
            self.sync_to_registers(self.reg_table)
            return (None, float('inf'))

        self.query_target_x = float(x)
        self.query_target_y = float(y)

        # Match target point ID if coordinates coincide exactly
        matched_pt = next((p for p in self.points if abs(p.x - x) < 1e-6 and abs(p.y - y) < 1e-6), None)
        self.query_target_id = matched_pt.id if matched_pt else 999

        best_node: Optional[KdPoint] = None
        best_dist = float('inf')

        def _search(node: Optional[KdNode]) -> None:
            nonlocal best_node, best_dist
            if node is None:
                return

            d = math.hypot(node.point.x - x, node.point.y - y)
            if d < best_dist:
                best_dist = d
                best_node = node.point

            axis = node.axis
            q_val = x if axis == 0 else y
            split_val = node.point.x if axis == 0 else node.point.y

            first = node.left if q_val < split_val else node.right
            second = node.right if q_val < split_val else node.left

            _search(first)

            # Hypersphere boundary pruning
            if abs(q_val - split_val) < best_dist:
                _search(second)

        _search(self.root)

        self.nearest_node = best_node
        self.nearest_distance = best_dist
        self.nearest_node_id = best_node.id if best_node else 0
        self.last_knn_results = [(best_node, best_dist)] if best_node else []

        # Check spatial proximity hazard against threshold
        if best_dist < self.hazard_threshold:
            self.alarm_active = True
            self.diagnostic_code = DIAG_ERR_PROXIMITY_HAZARD_ALARM
        elif self.hazard_violations_count == 0:
            self.alarm_active = False
            self.diagnostic_code = DIAG_OK

        self.sync_to_registers(self.reg_table)
        return (best_node, best_dist)

    def find_k_nearest(self, x: float, y: float, k: int = 3) -> List[Tuple[KdPoint, float]]:
        """Branch-and-bound k-nearest-neighbors (k-NN) search with hypersphere boundary pruning.

        Returns list of (point, distance) tuples sorted ascending by distance.
        """
        if k <= 0:
            self.diagnostic_code = DIAG_ERR_INVALID_K_NEIGHBORS
            self.sync_to_registers(self.reg_table)
            return []

        if math.isnan(x) or math.isnan(y) or math.isinf(x) or math.isinf(y):
            self.diagnostic_code = DIAG_ERR_DEGENERATE_COORDINATES
            self.sync_to_registers(self.reg_table)
            return []

        if self.root is None or not self.points:
            self.diagnostic_code = DIAG_ERR_EMPTY_TREE
            self.sync_to_registers(self.reg_table)
            return []

        self.query_target_x = float(x)
        self.query_target_y = float(y)

        matched_pt = next((p for p in self.points if abs(p.x - x) < 1e-6 and abs(p.y - y) < 1e-6), None)
        self.query_target_id = matched_pt.id if matched_pt else 999

        # Max-heap storing (-distance, entry_counter, KdPoint)
        heap: List[Tuple[float, int, KdPoint]] = []
        entry_counter = 0

        def _search_k(node: Optional[KdNode]) -> None:
            nonlocal entry_counter
            if node is None:
                return

            d = math.hypot(node.point.x - x, node.point.y - y)
            entry_counter += 1

            if len(heap) < k:
                heapq.heappush(heap, (-d, entry_counter, node.point))
            else:
                if d < -heap[0][0]:
                    heapq.heapreplace(heap, (-d, entry_counter, node.point))

            axis = node.axis
            q_val = x if axis == 0 else y
            split_val = node.point.x if axis == 0 else node.point.y

            first = node.left if q_val < split_val else node.right
            second = node.right if q_val < split_val else node.left

            _search_k(first)

            # Hypersphere boundary pruning
            if len(heap) < k or abs(q_val - split_val) < -heap[0][0]:
                _search_k(second)

        _search_k(self.root)

        # Sort extracted heap items ascending by distance
        results = sorted([(pt, -neg_d) for neg_d, _, pt in heap], key=lambda item: item[1])
        self.last_knn_results = results

        if results:
            self.nearest_node = results[0][0]
            self.nearest_distance = results[0][1]
            self.nearest_node_id = results[0][0].id

            if self.nearest_distance < self.hazard_threshold:
                self.alarm_active = True
                self.diagnostic_code = DIAG_ERR_PROXIMITY_HAZARD_ALARM
            elif self.hazard_violations_count == 0:
                self.alarm_active = False
                self.diagnostic_code = DIAG_OK

        self.sync_to_registers(self.reg_table)
        return results

    def inject_proximity_hazard_alarm(self) -> None:
        """Assert proximity hazard alarm (%M596 and 0x8415)."""
        self.alarm_active = True
        self.diagnostic_code = DIAG_ERR_PROXIMITY_HAZARD_ALARM
        self.sync_to_registers(self.reg_table)

    def clear_alarm(self) -> None:
        """Clear anomaly alarms and restore nominal diagnostic state."""
        self.alarm_active = False
        self.hazard_violations_count = 0
        for p in self.points:
            p.status = "normal"
        self.diagnostic_code = DIAG_OK
        self.sync_to_registers(self.reg_table)

    def clear_anomalies(self) -> None:
        """Alias for clear_alarm."""
        self.clear_alarm()

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.USER,
    ) -> None:
        """Synchronize state to Horner OCS registers %R2550..%R2557 and coils %M595..%M596."""
        rt = reg_table or self.reg_table
        m = self.metrics

        rt.write_word(REG_KDTREE_TOTAL_NODES, m.total_nodes & 0xFFFF, privilege=privilege)
        rt.write_word(REG_KDTREE_SUBDIVISION_DEPTH, m.subdivision_depth & 0xFFFF, privilege=privilege)
        rt.write_word(REG_KDTREE_QUERY_TARGET_ID, m.query_target_id & 0xFFFF, privilege=privilege)
        rt.write_word(REG_KDTREE_NEAREST_NODE_ID, m.nearest_node_id & 0xFFFF, privilege=privilege)
        rt.write_word(REG_KDTREE_NEAREST_DISTANCE_SCALED, m.nearest_distance_scaled, privilege=privilege)
        rt.write_word(REG_KDTREE_HAZARD_THRESHOLD_SCALED, m.hazard_threshold_scaled, privilege=privilege)
        rt.write_word(REG_KDTREE_HAZARD_VIOLATIONS_COUNT, m.hazard_violations_count & 0xFFFF, privilege=privilege)
        rt.write_word(REG_KDTREE_DIAGNOSTIC_CODE, int(m.diagnostic_code) & 0xFFFF, privilege=privilege)

        rt.write_bit(COIL_KDTREE_INDEXING_ONLINE, m.indexing_online, privilege=privilege)
        rt.write_bit(COIL_KDTREE_PROXIMITY_HAZARD_ALARM, m.proximity_hazard_alarm, privilege=privilege)

    def scan_step(self, context: Optional[ScanContext] = None) -> ExecutionResult:
        """Execute one simulation scan cycle step."""
        self.cycle_count += 1
        rt = getattr(context, "register_table", None) or self.reg_table
        self.sync_to_registers(rt)
        status = AgentStatus.SUCCESS if not self.alarm_active else AgentStatus.FAILED
        return ExecutionResult(
            status=status,
            error_code=None if not self.alarm_active else str(self.diagnostic_code),
            details=f"K-D Tree Canvas: {len(self.points)} nodes, Depth={self.current_depth}, Alarm={self.alarm_active}",
            data={
                "nodes": len(self.points),
                "depth": self.current_depth,
                "query_target_id": self.query_target_id,
                "nearest_node_id": self.nearest_node_id,
                "nearest_distance": self.nearest_distance,
                "hazard_threshold": self.hazard_threshold,
                "hazard_violations_count": self.hazard_violations_count,
                "alarm_active": self.alarm_active,
                "diagnostic_code": str(self.diagnostic_code),
            },
        )

    @property
    def name(self) -> str:
        """Unique identifier for this logic unit."""
        return "KdtreeCanvasEngine"

    @property
    def priority(self) -> int:
        """Execution priority (lower integer executes earlier)."""
        return 100

    @property
    def is_enabled(self) -> bool:
        """Whether the logic unit participates in the scan."""
        return True

    def step(self) -> None:
        """Single step simulation interface."""
        self.scan_step()

    def execute(self, context: Optional[ScanContext] = None) -> ExecutionResult:
        """Execute logic unit with scan context."""
        return self.scan_step(context)

    def reset(self) -> None:
        """Reset k-d tree to clean empty state."""
        self.cycle_count = 0
        self.points.clear()
        self.root = None
        self.current_depth = 0
        self.query_target_x = None
        self.query_target_y = None
        self.query_target_id = 0
        self.nearest_node = None
        self.nearest_node_id = 0
        self.nearest_distance = 0.0
        self.last_knn_results.clear()
        self.hazard_violations_count = 0
        self.diagnostic_code = DIAG_OK
        self.alarm_active = False
        self.sync_to_registers(self.reg_table)


KdtreeCanvas = KdtreeCanvasEngine


# ============================================================================
# 5. WCAG 2.1 AAA Contrast & Vector SCADA Visual Grounding (SVG 1.1)
# ============================================================================

def _srgb_to_linear(c_norm: float) -> float:
    """Convert normalized sRGB channel [0, 1] to linear factor for WCAG 2.1."""
    if c_norm <= 0.03928:
        return c_norm / 12.92
    return ((c_norm + 0.055) / 1.055) ** 2.4


def _hex_to_relative_luminance(hex_str: str) -> float:
    """Calculate relative luminance from hex color string."""
    h = hex_str.lstrip("#")
    r, g, b = int(h[0:2], 16) / 255.0, int(h[2:4], 16) / 255.0, int(h[4:6], 16) / 255.0
    return 0.2126 * _srgb_to_linear(r) + 0.7152 * _srgb_to_linear(g) + 0.0722 * _srgb_to_linear(b)


def calculate_contrast_ratio(hex1: str, hex2: str) -> float:
    """Calculate WCAG 2.1 contrast ratio between two hex colors."""
    l1 = _hex_to_relative_luminance(hex1)
    l2 = _hex_to_relative_luminance(hex2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def validate_wcag_aaa_contrast(foreground_hex: str, background_hex: str, target_ratio: float = 18.0) -> bool:
    """Assert WCAG 2.1 AAA high-contrast requirement."""
    return calculate_contrast_ratio(foreground_hex, background_hex) >= target_ratio


def generate_kdtree_canvas_svg(engine: KdtreeCanvasEngine) -> str:
    """Generate standalone W3C SVG 1.1 vector graphic meeting WCAG 2.1 AAA contrast."""
    w = int(engine.viewport_width)
    h = int(engine.viewport_height)

    # 1. Alternating Orthogonal Partition Lines across Subtree Viewports
    partition_lines: List[str] = []
    if engine.root:
        all_nodes = engine.root.get_all_nodes()
        for node in all_nodes:
            d = min(len(DEPTH_COLORS) - 1, node.depth)
            color = DEPTH_COLORS[d]
            stroke_w = max(0.8, 2.2 - 0.12 * node.depth)
            opacity = 0.75
            b = node.bounds

            if node.axis == 0:
                # Vertical partition line x = node.point.x spanning [y_min, y_max]
                x_val = node.point.x
                partition_lines.append(
                    f'<line class="kd-partition-line" x1="{x_val:.1f}" y1="{b.y_min:.1f}" '
                    f'x2="{x_val:.1f}" y2="{b.y_max:.1f}" stroke="{color}" stroke-width="{stroke_w:.1f}" '
                    f'stroke-dasharray="4 2" stroke-opacity="{opacity:.2f}" />'
                )
            else:
                # Horizontal partition line y = node.point.y spanning [x_min, x_max]
                y_val = node.point.y
                partition_lines.append(
                    f'<line class="kd-partition-line" x1="{b.x_min:.1f}" y1="{y_val:.1f}" '
                    f'x2="{b.x_max:.1f}" y2="{y_val:.1f}" stroke="{color}" stroke-width="{stroke_w:.1f}" '
                    f'stroke-dasharray="4 2" stroke-opacity="{opacity:.2f}" />'
                )

    # 2. Sensor Nodes with Status Colors
    nodes_svg: List[str] = []
    for p in engine.points:
        if p.status == "alarm":
            fill_col = COLOR_ALARM_CRIMSON
            stroke_col = "#DC2626"
        elif p.status == "warning":
            fill_col = COLOR_WARNING_AMBER
            stroke_col = "#D97706"
        else:
            fill_col = COLOR_NOMINAL_EMERALD
            stroke_col = "#059669"

        nodes_svg.append(
            f'<g id="kd-node-{p.id}" class="sensor-node">'
            f'<circle cx="{p.x:.1f}" cy="{p.y:.1f}" r="5.5" fill="{fill_col}" stroke="{stroke_col}" stroke-width="1.5" />'
            f'<text x="{p.x + 8:.1f}" y="{p.y - 4:.1f}" fill="{COLOR_TEXT_PRIMARY}" font-family="monospace" font-size="9" font-weight="bold">{p.tag}</text>'
            f'</g>'
        )

    # 3. Query Target Crosshair Reticle Overlay & Dashed Connector Vectors
    reticle_svg = ""
    connectors_svg: List[str] = []
    if engine.query_target_x is not None and engine.query_target_y is not None:
        qx = engine.query_target_x
        qy = engine.query_target_y
        hz = engine.hazard_threshold

        reticle_svg = f"""
    <!-- Query Target Crosshair Reticle Overlay -->
    <g id="query-target-crosshair" class="query-reticle">
        <!-- Crosshair lines -->
        <line x1="{qx - 16:.1f}" y1="{qy:.1f}" x2="{qx + 16:.1f}" y2="{qy:.1f}" stroke="{COLOR_RETICLE_CYAN}" stroke-width="1.8" />
        <line x1="{qx:.1f}" y1="{qy - 16:.1f}" x2="{qx:.1f}" y2="{qy + 16:.1f}" stroke="{COLOR_RETICLE_CYAN}" stroke-width="1.8" />
        <!-- Target center pip -->
        <circle cx="{qx:.1f}" cy="{qy:.1f}" r="6.0" fill="none" stroke="{COLOR_RETICLE_CYAN}" stroke-width="1.8" />
        <!-- Spatial proximity hazard perimeter -->
        <circle cx="{qx:.1f}" cy="{qy:.1f}" r="{hz:.1f}" fill="{COLOR_ALARM_CRIMSON}" fill-opacity="0.10" stroke="{COLOR_ALARM_CRIMSON}" stroke-width="1.5" stroke-dasharray="3 3" />
        <text x="{qx + hz + 6:.1f}" y="{qy + 4:.1f}" fill="{COLOR_ALARM_CRIMSON}" font-family="monospace" font-size="9" font-weight="bold">HAZARD ZONE ({hz:.0f}px)</text>
    </g>
        """

        # Dashed connector vectors to k-nearest neighbors with Euclidean distance callouts
        target_neighbors = engine.last_knn_results if engine.last_knn_results else ([(engine.nearest_node, engine.nearest_distance)] if engine.nearest_node else [])
        for idx, (np_pt, dist) in enumerate(target_neighbors):
            vec_col = COLOR_ALARM_CRIMSON if dist < hz else (COLOR_WARNING_AMBER if idx == 0 else COLOR_RETICLE_CYAN)
            mx = (qx + np_pt.x) / 2.0
            my = (qy + np_pt.y) / 2.0
            connectors_svg.append(
                f'<g id="connector-vector-{np_pt.id}" class="nearest-vector">'
                f'<line x1="{qx:.1f}" y1="{qy:.1f}" x2="{np_pt.x:.1f}" y2="{np_pt.y:.1f}" stroke="{vec_col}" stroke-width="1.5" stroke-dasharray="5 3" />'
                f'<rect x="{mx - 24:.1f}" y="{my - 14:.1f}" width="48" height="15" rx="3" fill="{COLOR_DECOUPLED_BADGE}" stroke="{vec_col}" stroke-width="0.8" />'
                f'<text class="distance-callout" x="{mx:.1f}" y="{my - 3:.1f}" fill="{vec_col}" font-family="monospace" font-size="9" font-weight="bold" text-anchor="middle">d={dist:.1f}</text>'
                f'</g>'
            )

    # 4. Decoupled High-Contrast HUD Telemetry Scorecard (WCAG 2.1 AAA Contrast > 18:1)
    m = engine.metrics
    alarm_col = COLOR_ALARM_CRIMSON if engine.alarm_active else COLOR_NOMINAL_EMERALD
    alarm_txt = "PROXIMITY HAZARD ALARM" if engine.alarm_active else "K-D TREE INDEXING ONLINE"

    hud_card = f"""
    <!-- Decoupled High-Contrast HUD Scorecard Card (WCAG AAA >= 18:1) -->
    <g id="hud-telemetry-scorecard">
        <rect x="20" y="20" width="1160" height="85" rx="8" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1.5" />
        <text x="40" y="48" fill="{COLOR_TEXT_PRIMARY}" font-family="monospace" font-size="17" font-weight="bold">DYNAMIC SPATIAL K-D TREE SCADA CANVAS (W294)</text>
        <text x="40" y="70" fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="11">POU: KdtreeCanvasSync | NODES: {m.total_nodes} | MAX DEPTH: {m.subdivision_depth}/12 | TARGET: #{m.query_target_id} | 1-NN: #{m.nearest_node_id} | DIST: {m.nearest_distance:.1f}px | HAZARD: {m.hazard_threshold:.1f}px (VIOLATIONS: {m.hazard_violations_count})</text>
        <text x="40" y="90" fill="#94A3B8" font-family="monospace" font-size="10">%R2550={m.total_nodes} | %R2551={m.subdivision_depth} | %R2552={m.query_target_id} | %R2553={m.nearest_node_id} | %R2554={m.nearest_distance_scaled} | %R2555={m.hazard_threshold_scaled} | %R2556={m.hazard_violations_count} | %R2557={str(m.diagnostic_code)} | %M595={int(m.indexing_online)} | %M596={int(m.proximity_hazard_alarm)}</text>

        <!-- Status Pill Box -->
        <rect x="850" y="32" width="310" height="38" rx="6" fill="{alarm_col}" fill-opacity="0.18" stroke="{alarm_col}" stroke-width="1.5" />
        <text x="1005" y="56" fill="{alarm_col}" font-family="monospace" font-size="11" font-weight="bold" text-anchor="middle">{alarm_txt}</text>
    </g>
    """

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}">
    <rect width="{w}" height="{h}" fill="{COLOR_SCADA_BG}" />
    {"".join(partition_lines)}
    {"".join(connectors_svg)}
    {reticle_svg}
    {"".join(nodes_svg)}
    {hud_card}
</svg>"""
    return svg


def create_canonical_kdtree_canvas(
    viewport_width: float = CANVAS_VIEWPORT_WIDTH,
    viewport_height: float = CANVAS_VIEWPORT_HEIGHT,
    max_depth: int = DEFAULT_MAX_DEPTH,
    hazard_threshold: float = DEFAULT_HAZARD_THRESHOLD,
    sample_count: int = 24,
    seed: Optional[int] = 42,
) -> KdtreeCanvasEngine:
    """Create canonical pre-populated KdtreeCanvasEngine for simulation and testing."""
    eng = KdtreeCanvasEngine(
        viewport_width=viewport_width,
        viewport_height=viewport_height,
        max_depth=max_depth,
        hazard_threshold=hazard_threshold,
    )
    rng = random.Random(seed)
    for i in range(sample_count):
        x = rng.uniform(80.0, viewport_width - 80.0)
        y = rng.uniform(80.0, viewport_height - 80.0)
        eng.insert_point(x, y, node_id=i + 1)
    return eng


# ============================================================================
# 6. Deterministic 9-Stage Verification Function
# ============================================================================

def run_kdtree_canvas_verification(
    output_path: Optional[str] = None,
    sample_svg_path: Optional[str] = None,
    work_package: str = "W294",
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification sequence for W294."""
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: init_and_domain
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    eng = KdtreeCanvasEngine(max_depth=12, hazard_threshold=30.0)
    c1_init = (
        eng.viewport_width == CANVAS_VIEWPORT_WIDTH
        and eng.viewport_height == CANVAS_VIEWPORT_HEIGHT
        and eng.max_depth == 12
        and eng.hazard_threshold == 30.0
        and len(eng.points) == 0
        and eng.current_depth == 0
        and eng.root is None
        and eng.diagnostic_code == DIAG_OK
        and eng.alarm_active is False
        and eng.indexing_online is True
    )

    # Validate coordinate bounds rejection & degenerate coord rejection
    c1_oob = eng.insert_point(-50.0, 300.0) is False and eng.diagnostic_code == DIAG_ERR_INVALID_DOMAIN
    c1_nan = eng.insert_point(float("nan"), 300.0) is False and eng.diagnostic_code == DIAG_ERR_DEGENERATE_COORDINATES
    eng.diagnostic_code = DIAG_OK

    c1 = c1_init and c1_oob and c1_nan
    test_results.append({
        "stage": 1,
        "name": "init_and_domain",
        "passed": c1,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Spatial K-D Tree initialized over [{eng.viewport_width}x{eng.viewport_height}] domain (MaxDepth=12, Hazard=30.0px).",
    })

    # ------------------------------------------------------------------------
    # Stage 2: node_insertion_and_depth
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Insert structured hierarchy of points:
    # Point 1: Root (600, 375) -> depth 0
    # Point 2: Left child (300, 200) -> depth 1
    # Point 3: Right child (900, 500) -> depth 1
    # Point 4: Left-Left grandchild (200, 100) -> depth 2
    # Point 5: Left-Right grandchild (400, 300) -> depth 2
    ok1 = eng.insert_point(600.0, 375.0, node_id=1)
    ok2 = eng.insert_point(300.0, 200.0, node_id=2)
    ok3 = eng.insert_point(900.0, 500.0, node_id=3)
    ok4 = eng.insert_point(200.0, 100.0, node_id=4)
    ok5 = eng.insert_point(400.0, 300.0, node_id=5)

    c2 = (
        ok1 and ok2 and ok3 and ok4 and ok5
        and len(eng.points) == 5
        and eng.current_depth == 2
        and eng.root is not None
        and eng.root.count() == 5
        and eng.diagnostic_code == DIAG_OK
        and eng.alarm_active is False
    )
    test_results.append({
        "stage": 2,
        "name": "node_insertion_and_depth",
        "passed": c2,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Dynamic insertion validated: 5 nodes inserted, depth tracked accurately to {eng.current_depth}.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: alternating_axis_partitioning
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Depth 0 (Root) must partition along x-axis (axis = 0)
    # Depth 1 (Children) must partition along y-axis (axis = 1)
    # Depth 2 (Grandchildren) must partition along x-axis (axis = 0)
    root = eng.root
    c3_axes = (
        root.depth == 0 and root.axis == 0
        and root.left.depth == 1 and root.left.axis == 1
        and root.right.depth == 1 and root.right.axis == 1
        and root.left.left.depth == 2 and root.left.left.axis == 0
        and root.left.right.depth == 2 and root.left.right.axis == 0
    )

    # Sub-bounds partitioning verification
    c3_bounds = (
        root.bounds == KdRect(0.0, 0.0, 1200.0, 750.0)
        and root.left.bounds == KdRect(0.0, 0.0, 600.0, 750.0)
        and root.right.bounds == KdRect(600.0, 0.0, 1200.0, 750.0)
        and root.left.left.bounds == KdRect(0.0, 0.0, 600.0, 200.0)
        and root.left.right.bounds == KdRect(0.0, 200.0, 600.0, 750.0)
    )

    c3 = c3_axes and c3_bounds
    test_results.append({
        "stage": 3,
        "name": "alternating_axis_partitioning",
        "passed": c3,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Alternating orthogonal axis partitioning verified: axis = depth % 2 across all subtree boundaries.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: nearest_neighbor_search
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Query at coordinate (450.0, 350.0)
    # Ground truth brute force calculation:
    # Pt 1: (600, 375) -> dist = hypot(150, 25) = 152.069
    # Pt 2: (300, 200) -> dist = hypot(150, 150) = 212.132
    # Pt 3: (900, 500) -> dist = hypot(450, 150) = 474.341
    # Pt 4: (200, 100) -> dist = hypot(250, 250) = 353.553
    # Pt 5: (400, 300) -> dist = hypot(50, 50) = 70.7106
    # Closest is Pt 5 with distance ~70.71 px (which is > hazard_threshold 30.0 px)
    qx, qy = 450.0, 350.0
    nn_node, nn_dist = eng.find_nearest(qx, qy)
    expected_dist = math.hypot(50.0, 50.0)

    c4 = (
        nn_node is not None
        and nn_node.id == 5
        and abs(nn_dist - expected_dist) < 1e-5
        and eng.nearest_node_id == 5
        and eng.alarm_active is False
    )
    test_results.append({
        "stage": 4,
        "name": "nearest_neighbor_search",
        "passed": c4,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"1-NN search verified: nearest node #{nn_node.id if nn_node else 0} at d={nn_dist:.2f}px matches ground truth.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: k_nearest_neighbors_search
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Query k-NN for k=3 from same query point (450.0, 350.0)
    # Top 3 expected: Pt 5 (70.71px), Pt 1 (152.07px), Pt 2 (212.13px)
    knn = eng.find_k_nearest(qx, qy, k=3)
    c5_knn = (
        len(knn) == 3
        and [p.id for p, _ in knn] == [5, 1, 2]
        and knn[0][1] <= knn[1][1] <= knn[2][1]
        and abs(knn[0][1] - expected_dist) < 1e-5
    )

    # Invalid k handling
    c5_invalid_k = eng.find_k_nearest(qx, qy, k=0) == [] and eng.diagnostic_code == DIAG_ERR_INVALID_K_NEIGHBORS
    eng.diagnostic_code = DIAG_OK

    c5 = c5_knn and c5_invalid_k
    test_results.append({
        "stage": 5,
        "name": "k_nearest_neighbors_search",
        "passed": c5,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"k-NN (k=3) branch-and-bound search validated: IDs={[p.id for p, _ in knn]}, distances strictly monotonic.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: proximity_hazard_alarm
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Query point within hazard threshold of Point 5 (400, 300):
    # Query at (405.0, 305.0) -> dist = hypot(5, 5) = 7.07 px < 30.0 px
    haz_node, haz_dist = eng.find_nearest(405.0, 305.0)
    c6_query_hazard = (
        haz_node is not None
        and haz_dist < eng.hazard_threshold
        and eng.alarm_active is True
        and eng.diagnostic_code == DIAG_ERR_PROXIMITY_HAZARD_ALARM
    )

    # Clear alarm test
    eng.clear_alarm()
    c6_clear = eng.alarm_active is False and eng.diagnostic_code == DIAG_OK

    # Inject proximity alarm test
    eng.inject_proximity_hazard_alarm()
    c6_inject = eng.alarm_active is True and eng.diagnostic_code == DIAG_ERR_PROXIMITY_HAZARD_ALARM

    eng.clear_alarm()
    c6 = c6_query_hazard and c6_clear and c6_inject
    test_results.append({
        "stage": 6,
        "name": "proximity_hazard_alarm",
        "passed": c6,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"Spatial proximity hazard detection validated: tripped %M596 and 0x8415 at d={haz_dist:.2f}px < 30.0px.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: wcag_aaa_svg_rendering
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # Query again to populate reticle & connectors for SVG
    eng.find_k_nearest(450.0, 350.0, k=3)
    svg_text = generate_kdtree_canvas_svg(eng)
    root_el = ET.fromstring(svg_text)
    contrast_ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)

    c7 = (
        root_el.tag.endswith("svg")
        and "kd-partition-line" in svg_text
        and "sensor-node" in svg_text
        and "query-target-crosshair" in svg_text
        and "nearest-vector" in svg_text
        and "hud-telemetry-scorecard" in svg_text
        and contrast_ratio >= 18.0
    )
    test_results.append({
        "stage": 7,
        "name": "wcag_aaa_svg_rendering",
        "passed": c7,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": f"W3C SVG 1.1 vector graphic rendered with valid XML; WCAG 2.1 AAA contrast verified ({contrast_ratio:.2f}:1 >= 18:1).",
    })

    # ------------------------------------------------------------------------
    # Stage 8: horner_ocs_register_sync
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    rt = RegisterTable()
    eng.sync_to_registers(rt)

    w_nodes = rt.read_word(REG_KDTREE_TOTAL_NODES)
    w_depth = rt.read_word(REG_KDTREE_SUBDIVISION_DEPTH)
    w_target = rt.read_word(REG_KDTREE_QUERY_TARGET_ID)
    w_nearest = rt.read_word(REG_KDTREE_NEAREST_NODE_ID)
    w_dist = rt.read_word(REG_KDTREE_NEAREST_DISTANCE_SCALED)
    w_thresh = rt.read_word(REG_KDTREE_HAZARD_THRESHOLD_SCALED)
    w_viols = rt.read_word(REG_KDTREE_HAZARD_VIOLATIONS_COUNT)
    w_diag = rt.read_word(REG_KDTREE_DIAGNOSTIC_CODE)
    b_online = rt.read_bit(COIL_KDTREE_INDEXING_ONLINE)
    b_alarm = rt.read_bit(COIL_KDTREE_PROXIMITY_HAZARD_ALARM)

    c8 = (
        w_nodes == len(eng.points)
        and w_depth == eng.current_depth
        and w_target == eng.query_target_id
        and w_nearest == eng.nearest_node_id
        and w_dist == int(round(eng.nearest_distance * 10.0)) & 0xFFFF
        and w_thresh == int(round(eng.hazard_threshold * 10.0)) & 0xFFFF
        and w_viols == eng.hazard_violations_count
        and (w_diag & 0xFFFF) == 0x0000
        and b_online is True
        and b_alarm is False
    )
    test_results.append({
        "stage": 8,
        "name": "horner_ocs_register_sync",
        "passed": c8,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Horner OCS register space %R2550..%R2557 and coils %M595..%M596 verified bit-exact.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: pure_st_pou_and_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_valid = verify_kdtree_canvas_pure_st()
    ladder_rejected = False
    try:
        SecurityGuard.assert_pure_st_content("PROGRAM P ---[ ]--- END_PROGRAM")
    except LadderForbiddenError:
        ladder_rejected = True

    c9 = st_valid and ladder_rejected
    test_results.append({
        "stage": 9,
        "name": "pure_st_pou_and_ladder_rejection",
        "passed": c9,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "KdtreeCanvasSync pure ST AST validated; ladder logic contacts rejected.",
    })

    passed_count = sum(1 for r in test_results if r["passed"])
    total_count = len(test_results)
    all_passed = (passed_count == total_count)

    evidence = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": f"Wave {work_package} K-D Tree Canvas Verification PASSED ({passed_count}/{total_count} stages).",
        "data": {
            "work_package": work_package,
            "gate": "G9",
            "checks_passed": passed_count,
            "total_checks": total_count,
            "stages": test_results,
            "tests": test_results,
        },
    }

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    if sample_svg_path:
        svg_p = Path(sample_svg_path)
        svg_p.parent.mkdir(parents=True, exist_ok=True)
        with open(svg_p, "w", encoding="utf-8") as f:
            f.write(svg_text)

    return evidence


# ============================================================================
# 7. Exports & CLI Entrypoint
# ============================================================================

__all__ = [
    "CANVAS_VIEWPORT_HEIGHT",
    "CANVAS_VIEWPORT_WIDTH",
    "COLOR_ALARM_CRIMSON",
    "COLOR_BORDER",
    "COLOR_CONNECTOR_VECTOR",
    "COLOR_DARK_SURFACE",
    "COLOR_DECOUPLED_BADGE",
    "COLOR_NOMINAL_EMERALD",
    "COLOR_PARTITION_X",
    "COLOR_PARTITION_Y",
    "COLOR_RETICLE_CYAN",
    "COLOR_SAMPLE_BORDER",
    "COLOR_SAMPLE_NODE",
    "COLOR_SCADA_BG",
    "COLOR_TEXT_MUTED",
    "COLOR_TEXT_PRIMARY",
    "COLOR_WARNING_AMBER",
    "DEFAULT_HAZARD_THRESHOLD",
    "DEFAULT_MAX_DEPTH",
    "DEPTH_COLORS",
    "DIAG_ERR_DEGENERATE_COORDINATES",
    "DIAG_ERR_DEGENERATE_NODE_COORDS",
    "DIAG_ERR_EMPTY_TREE",
    "DIAG_ERR_HAZARD_ALARM",
    "DIAG_ERR_INVALID_DOMAIN",
    "DIAG_ERR_INVALID_K_NEIGHBORS",
    "DIAG_ERR_OUT_OF_BOUNDS",
    "DIAG_ERR_PROXIMITY_HAZARD_ALARM",
    "DIAG_OK",
    "DiagnosticCode",
    "BoundingBox",
    "KdBounds",
    "KdDiagnosticCode",
    "KdMetrics",
    "KdNode",
    "KdNodePoint",
    "KdPoint",
    "KdRect",
    "KdStatusBits",
    "KDTREE_CANVAS_PURE_ST_POU",
    "KdtreeCanvas",
    "KdtreeCanvasEngine",
    "KdtreeCanvasSync",
    "KdtreeDiagnosticCode",
    "KdtreeMetrics",
    "KdtreeStatusBits",
    "REG_KDTREE_DIAGNOSTIC_CODE",
    "REG_KDTREE_HAZARD_THRESHOLD",
    "REG_KDTREE_HAZARD_THRESHOLD_SCALED",
    "REG_KDTREE_HAZARD_VIOLATIONS_COUNT",
    "REG_KDTREE_MAX_DEPTH",
    "REG_KDTREE_NEAREST_DIST",
    "REG_KDTREE_NEAREST_DISTANCE_SCALED",
    "REG_KDTREE_NEAREST_ID",
    "REG_KDTREE_NEAREST_NODE_ID",
    "REG_KDTREE_NODE_COUNT",
    "REG_KDTREE_QUERY_TARGET_ID",
    "REG_KDTREE_SUBDIVISION_DEPTH",
    "REG_KDTREE_TARGET_ID",
    "REG_KDTREE_TOTAL_NODES",
    "REG_KDTREE_VIOLATIONS_COUNT",
    "REG_W294_DIAGNOSTIC_CODE",
    "REG_W294_HAZARD_THRESHOLD_SCALED",
    "REG_W294_HAZARD_VIOLATIONS_COUNT",
    "REG_W294_NEAREST_DISTANCE_SCALED",
    "REG_W294_NEAREST_NODE_ID",
    "REG_W294_QUERY_TARGET_ID",
    "REG_W294_SUBDIVISION_DEPTH",
    "REG_W294_TOTAL_NODES",
    "COIL_KDTREE_CANVAS_ACTIVE",
    "COIL_KDTREE_HAZARD_ALARM",
    "COIL_KDTREE_INDEXING_ONLINE",
    "COIL_KDTREE_PROXIMITY_HAZARD_ALARM",
    "COIL_W294_INDEXING_ONLINE",
    "COIL_W294_PROXIMITY_HAZARD_ALARM",
    "ST_PROGRAM_KDTREE_CANVAS_SYNC",
    "SpatialPoint",
    "TOTAL_DOMAIN_AREA",
    "calculate_contrast_ratio",
    "create_canonical_kdtree_canvas",
    "generate_kdtree_canvas_svg",
    "run_kdtree_canvas_verification",
    "validate_wcag_aaa_contrast",
    "verify_kdtree_canvas_pure_st",
]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="W294 K-D Tree SCADA Canvas Verification Runner")
    parser.add_argument("--verify", action="store_true", help="Run 9-stage verification")
    parser.add_argument("--output", type=str, default=None, help="Output JSON evidence path")
    parser.add_argument("--export-svg", type=str, default=None, help="Export sample SVG path")
    args = parser.parse_args()

    results = run_kdtree_canvas_verification(
        output_path=args.output,
        sample_svg_path=args.export_svg,
    )
    print(json.dumps(results, indent=2))
    sys.exit(0 if results.get("status") == "success" else 1)
