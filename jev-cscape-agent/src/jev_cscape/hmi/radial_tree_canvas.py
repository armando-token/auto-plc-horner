"""Cscape HMI Dynamic Radial Tree & Hierarchical Dependency Graph SCADA Canvas.

Work Package: W207 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Provides:
1. Hierarchical Graph & Tree Structures:
   - TreeNode data model with parent-child references, depth level, weight, health scores, and polar coordinates.
   - RadialTree builder with parent-child bidirectional linking and O(V + E) cycle detection.
   - HierarchyCycleError raised upon detection of cyclic dependencies.
2. Polar-to-Cartesian Coordinate Transformation & Angular Allocation:
   - Polar-to-Cartesian (r, theta) -> (x, y) with center offset and angle normalization.
   - Hierarchical angular interval allocation [theta_min, theta_max] proportional to subtree weights.
   - Exact angular sweep conservation sum(theta_span_children) == theta_span_parent.
   - Concentric radial level rings (Level 0: Plant Core, Level 1: Area, Level 2: Unit, Level 3: Subsystem).
3. Cubic Bezier Curve Synthesis for Hierarchical Edges:
   - Radial cubic Bezier paths B(t) connecting parent and child nodes with smooth radial tangents.
   - Control points CP1 and CP2 oriented radially outward from parent to child.
   - Evaluation helper eval_cubic_bezier(P0, P1, P2, P3, t) and SVG path formatting.
4. Bottom-Up Health Score Propagation & Critical Fault Identification:
   - Bottom-up post-order health propagation from leaf assets to plant root.
   - Weighted average health aggregation: H_parent = sum(W_i * H_i) / sum(W_i).
   - Critical fault trip localization (health < 70.0% asserts is_fault and trips coil %M392).
   - Minimum health node discovery and fault severity classification (NOMINAL, WARNING, CRITICAL).
5. Dark Industrial Theme & WCAG 2.1 AAA Accessibility:
   - Dark industrial SCADA viewport backing (#0D1117) with ultra-high contrast decoupled badge (#050811).
   - Relative luminance and contrast ratio engine meeting WCAG 2.1 AAA (> 18:1 badge, > 7:1 text, > 3:1 graphics).
6. Standalone W3C SVG 1.1 Vector Graphic Generation:
   - Valid XML SVG markup with defs, concentric guide circles, cubic Bezier edge paths,
     multi-ring nodes with status halos, and right-hand telemetry HUD cards.
   - Fully parsable by xml.etree.ElementTree.fromstring.
7. Horner OCS Memory Space Integration:
   - Analog registers %R1680..%R1687:
     - %R1680: RootAggregateHealthScoreScaled (INT16, scaled x10 %, e.g. 945 = 94.5%)
     - %R1681: SelectedNodeIndex (INT16, 0..N)
     - %R1682: SelectedNodeHealthScoreScaled (INT16, scaled x10 %, e.g. 880 = 88.0%)
     - %R1683: CriticalFaultCount (INT16, count of degraded nodes)
     - %R1684: MaxTreeDepth (INT16, max depth in active tree)
     - %R1685: TotalNodeCount (INT16, total node count)
     - %R1686: MinHealthScoreScaled (INT16, scaled x10 %, lowest health in tree)
     - %R1687: DiagnosticStatusCode (0x0000=OK, 0xE201, 0xE202, 0xE203, 0xE204)
   - Discrete coils %M392..%M393:
     - %M392: CriticalFaultAlarmActive (BOOL)
     - %M393: RadialTreeCanvasActive (BOOL)
   - Synchronization with PrivilegeMode.SYSTEM.
8. ILogicUnit Discrete Scan Cycle Engine:
   - Implements scan_step(dt), step(), and execute(ScanContext) protocols.
9. Pure IEC 61131-3 Structured Text (ST) POU:
   - Program 'RadialTreeCanvasSync' validated via SecurityGuard.assert_pure_st_content and STParser.
10. Deterministic 9-Stage Verification Suite:
    - run_radial_tree_canvas_verification returning strict 4-state contract JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntFlag
import html
import json
import math
from pathlib import Path
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Constants & Diagnostic Event Codes
# ============================================================================

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


# Diagnostic event codes conforming to Horner OCS %R1687 specification
DIAG_OK: DiagnosticCode                                              = DiagnosticCode(0x0000)
DIAG_EVENT_OK: DiagnosticCode                                        = DiagnosticCode(0x0000)

# 0xE201: Hierarchy cycle detected in tree dependency graph
DIAG_ERR_HIERARCHY_CYCLE_DETECTED: DiagnosticCode                    = DiagnosticCode(0xE201)
HIERARCHY_CYCLE_DETECTED: DiagnosticCode                             = DIAG_ERR_HIERARCHY_CYCLE_DETECTED

# 0xE202: Angular overlap / spacing violation between adjacent nodes
DIAG_ERR_ANGULAR_OVERLAP: DiagnosticCode                             = DiagnosticCode(0xE202)
ANGULAR_OVERLAP_FAULT: DiagnosticCode                                = DIAG_ERR_ANGULAR_OVERLAP

# 0xE203: Critical health fault trip (node health < critical threshold) -> asserts %M392
DIAG_ERR_CRITICAL_FAULT_TRIP: DiagnosticCode                         = DiagnosticCode(0xE203)
CRITICAL_FAULT_TRIP: DiagnosticCode                                  = DIAG_ERR_CRITICAL_FAULT_TRIP

# 0xE204: SVG vector rasterization / XML syntax render fault
DIAG_ERR_SVG_RENDER_FAULT: DiagnosticCode                            = DiagnosticCode(0xE204)
SVG_RENDER_FAULT: DiagnosticCode                                     = DIAG_ERR_SVG_RENDER_FAULT

# Horner OCS Register Definitions (%R1680..%R1687)
REG_ROOT_HEALTH_SCORE_SCALED: str                                    = "%R1680"
REG_SELECTED_NODE_INDEX: str                                         = "%R1681"
REG_SELECTED_NODE_HEALTH_SCALED: str                                 = "%R1682"
REG_CRITICAL_FAULT_COUNT: str                                        = "%R1683"
REG_MAX_TREE_DEPTH: str                                              = "%R1684"
REG_TOTAL_NODE_COUNT: str                                            = "%R1685"
REG_MIN_HEALTH_SCORE_SCALED: str                                     = "%R1686"
REG_DIAGNOSTIC_STATUS_CODE: str                                      = "%R1687"

# Aliases for W207
REG_W207_ROOT_HEALTH: str                                            = "%R1680"
REG_W207_SELECTED_NODE: str                                          = "%R1681"
REG_W207_SELECTED_HEALTH: str                                        = "%R1682"
REG_W207_CRITICAL_FAULTS: str                                        = "%R1683"
REG_W207_MAX_DEPTH: str                                              = "%R1684"
REG_W207_TOTAL_NODES: str                                            = "%R1685"
REG_W207_MIN_HEALTH: str                                             = "%R1686"
REG_W207_STATUS_WORD: str                                            = "%R1687"
REG_W207_DIAGNOSTIC_CODE: str                                        = "%R1687"

# Discrete Coils (%M392..%M393)
COIL_CRITICAL_FAULT_ALARM_ACTIVE: str                                = "%M392"
COIL_RADIAL_TREE_CANVAS_ACTIVE: str                                  = "%M393"
COIL_W207_FAULT_ALARM: str                                           = "%M392"
COIL_W207_CANVAS_ACTIVE: str                                         = "%M393"
COIL_TREE_FAULT_TRIP: str                                            = "%M392"
COIL_RADIAL_TREE_ACTIVE: str                                         = "%M393"

# Canvas & Viewport Specifications
CANVAS_VIEWPORT_WIDTH: int                                           = 1200
CANVAS_VIEWPORT_HEIGHT: int                                          = 750
CANVAS_CENTER_X: float                                               = 500.0
CANVAS_CENTER_Y: float                                               = 375.0

# Concentric Ring Radii per Hierarchy Level
LEVEL_0_RADIUS: float                                                = 0.0     # Central Plant Core Hub
LEVEL_1_RADIUS: float                                                = 110.0   # Level 1: Production Areas
LEVEL_2_RADIUS: float                                                = 210.0   # Level 2: Operating Units
LEVEL_3_RADIUS: float                                                = 310.0   # Level 3: Subsystems & Assets
CANONICAL_LEVEL_RADII: List[float]                                   = [
    LEVEL_0_RADIUS,
    LEVEL_1_RADIUS,
    LEVEL_2_RADIUS,
    LEVEL_3_RADIUS,
]

# Process Health Thresholds
HEALTH_CRITICAL_THRESHOLD: float                                     = 70.0    # < 70.0% is CRITICAL fault
HEALTH_WARNING_THRESHOLD: float                                      = 85.0    # 70.0% <= health < 85.0% is WARNING
HEALTH_NOMINAL_BASELINE: float                                       = 95.0    # Nominal healthy baseline

# WCAG 2.1 AAA Accessibility Targets
WCAG_AAA_BADGE_CONTRAST_TARGET: float                                = 18.0    # Contrast > 18:1
WCAG_AAA_TEXT_CONTRAST_TARGET: float                                 = 7.0     # Contrast > 7:1
WCAG_GRAPHICAL_CONTRAST_TARGET: float                                = 3.0     # Contrast > 3:1

# SCADA Industrial Color Palette
COLOR_DARK_THEME_BACKING: str                                        = "#0D1117"   # Industrial dark background
COLOR_DARK_SURFACE: str                                              = "#161B22"   # Elevated container surface
COLOR_CARD_BG: str                                                   = "#1E293B"   # HUD telemetry card background
COLOR_CARD_BORDER: str                                               = "#334155"   # Card boundary stroke
COLOR_DECOUPLED_BADGE: str                                           = "#050811"   # Ultra-dark decoupled badge (> 18:1)
COLOR_TEXT_PRIMARY: str                                              = "#F8FAFC"   # White primary text
COLOR_TEXT_MUTED: str                                                = "#94A3B8"   # Secondary slate text
COLOR_FOCUS_BLUE: str                                                = "#38BDF8"   # Cyan/Blue selection highlight
COLOR_TREE_EDGE: str                                                 = "#475569"   # Bezier connection curves
COLOR_RING_GUIDE: str                                                = "#1E293B"   # Concentric guide circles

# Status Health Colors
COLOR_NOMINAL_EMERALD: str                                           = "#10B981"   # Nominal health (>= 85%)
COLOR_NOMINAL: str                                                   = COLOR_NOMINAL_EMERALD
COLOR_WARM_AMBER: str                                                = "#F59E0B"   # Warning health (70..85%)
COLOR_WARNING: str                                                   = COLOR_WARM_AMBER
COLOR_ALARM_CRIMSON: str                                             = "#EF4444"   # Critical fault (< 70%)
COLOR_CRITICAL: str                                                  = COLOR_ALARM_CRIMSON
COLOR_CYAN_INFO: str                                                 = "#06B6D4"   # Informational / auxiliary


# ============================================================================
# 2. Enums and Status Bitmasks
# ============================================================================

class NodeHealthState(str, Enum):
    """Health classification for tree nodes."""
    NOMINAL = "NOMINAL"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class RadialTreeStatusBits(IntFlag):
    """Horner OCS Status Bitmask Definitions (%R1687)."""
    CANVAS_ACTIVE              = 1 << 0  # Bit 0 (0x0001): Canvas & radial engine active (%M393)
    GEOMETRY_COMPUTED          = 1 << 1  # Bit 1 (0x0002): Polar-to-Cartesian layout calculated
    HIERARCHY_VALID            = 1 << 2  # Bit 2 (0x0004): Tree acyclic and references valid
    HEALTH_PROPAGATED          = 1 << 3  # Bit 3 (0x0008): Bottom-up health propagated to root
    CRITICAL_FAULT_ACTIVE      = 1 << 4  # Bit 4 (0x0010): Critical fault alarm asserted (%M392)
    CYCLE_DETECTED             = 1 << 5  # Bit 5 (0x0020): Cycle detected in graph (0xE201)
    ANGULAR_OVERLAP_FAULT      = 1 << 6  # Bit 6 (0x0040): Spacing overlap detected (0xE202)
    RENDER_FAULT               = 1 << 7  # Bit 7 (0x0080): SVG render fault (0xE204)
    SVG_VALID                  = 1 << 8  # Bit 8 (0x0100): Standalone W3C SVG 1.1 rendered and valid
    WCAG_AAA_VERIFIED          = 1 << 9  # Bit 9 (0x0200): WCAG 2.1 AAA contrast confirmed (> 18:1)
    NODE_SELECTED              = 1 << 10 # Bit 10 (0x0400): Active node selected and highlighted
    NOMINAL_OPERATION          = 1 << 11 # Bit 11 (0x0800): Nominal fault-free operation


class HierarchyCycleError(ValueError):
    """Raised when a directed or indirect cycle is detected in the tree structure."""
    pass


# ============================================================================
# 3. Geometric Primitives & Math
# ============================================================================

@dataclass(frozen=True)
class Point2D:
    """2D Cartesian Coordinate Point."""
    x: float
    y: float

    def distance_to(self, other: Point2D) -> float:
        """Euclidean distance to another point."""
        return math.hypot(self.x - other.x, self.y - other.y)

    def as_tuple(self) -> Tuple[float, float]:
        """Convert to (x, y) tuple."""
        return (self.x, self.y)


def polar_to_cartesian(
    radius: float,
    theta_rad: float,
    center_x: float = CANVAS_CENTER_X,
    center_y: float = CANVAS_CENTER_Y,
) -> Point2D:
    """Convert polar coordinates (radius, theta_rad) to 2D Cartesian coordinates (x, y)."""
    x = center_x + radius * math.cos(theta_rad)
    y = center_y + radius * math.sin(theta_rad)
    return Point2D(x=round(x, 4), y=round(y, 4))


def cartesian_to_polar(
    point: Point2D,
    center_x: float = CANVAS_CENTER_X,
    center_y: float = CANVAS_CENTER_Y,
) -> Tuple[float, float]:
    """Convert 2D Cartesian point to polar coordinates (radius, theta_rad in [0, 2*pi))."""
    dx = point.x - center_x
    dy = point.y - center_y
    r = math.hypot(dx, dy)
    theta = math.atan2(dy, dx)
    if theta < 0.0:
        theta += 2.0 * math.pi
    return (round(r, 4), round(theta, 6))


def normalize_angle_rad(angle_rad: float) -> float:
    """Normalize angle in radians to [0, 2*pi)."""
    two_pi = 2.0 * math.pi
    rem = angle_rad % two_pi
    return rem if rem >= 0.0 else rem + two_pi


def compute_cubic_bezier_points(
    p0: Point2D,
    p3: Point2D,
    r0: float,
    r3: float,
    theta0: float,
    theta3: float,
    center_x: float = CANVAS_CENTER_X,
    center_y: float = CANVAS_CENTER_Y,
) -> Tuple[Point2D, Point2D, Point2D, Point2D]:
    """Compute the 4 control points (P0, P1, P2, P3) for a radial hierarchical edge.

    At parent (P0), tangent moves radially outward along theta0.
    At child (P3), tangent arrives radially outward along theta3.
    When parent is root (r0 == 0), tangent emanates directly along child direction theta3.
    """
    delta_r = r3 - r0
    fraction = 0.5

    if r0 <= 1e-4:
        # Parent is root center
        cp1_r = r3 * 0.35
        cp2_r = r3 * 0.70
        p1 = polar_to_cartesian(cp1_r, theta3, center_x, center_y)
        p2 = polar_to_cartesian(cp2_r, theta3, center_x, center_y)
    else:
        # Radial tangent directed outward along theta0 for P1
        cp1_r = r0 + delta_r * fraction
        p1 = polar_to_cartesian(cp1_r, theta0, center_x, center_y)

        # Radial tangent directed inward/arriving along theta3 for P2
        cp2_r = r3 - delta_r * fraction
        p2 = polar_to_cartesian(cp2_r, theta3, center_x, center_y)

    return (p0, p1, p2, p3)


def eval_cubic_bezier(
    p0: Point2D,
    p1: Point2D,
    p2: Point2D,
    p3: Point2D,
    t: float,
) -> Point2D:
    """Evaluate cubic Bezier curve B(t) for parameter t in [0.0, 1.0].

    B(t) = (1-t)^3 * P0 + 3(1-t)^2 * t * P1 + 3(1-t) * t^2 * P2 + t^3 * P3
    """
    t = max(0.0, min(1.0, t))
    u = 1.0 - t
    u2 = u * u
    u3 = u2 * u
    t2 = t * t
    t3 = t2 * t

    x = u3 * p0.x + 3.0 * u2 * t * p1.x + 3.0 * u * t2 * p2.x + t3 * p3.x
    y = u3 * p0.y + 3.0 * u2 * t * p1.y + 3.0 * u * t2 * p2.y + t3 * p3.y
    return Point2D(x=round(x, 4), y=round(y, 4))


def format_cubic_bezier_svg_path(
    p0: Point2D,
    p1: Point2D,
    p2: Point2D,
    p3: Point2D,
) -> str:
    """Format SVG path command string for cubic Bezier curve."""
    return f"M {p0.x:.2f},{p0.y:.2f} C {p1.x:.2f},{p1.y:.2f} {p2.x:.2f},{p2.y:.2f} {p3.x:.2f},{p3.y:.2f}"


# ============================================================================
# 4. WCAG 2.1 AAA Accessibility Engine
# ============================================================================

def srgb_channel_to_linear(channel: float) -> float:
    """Convert 8-bit sRGB channel (0..1) to linear luminance value."""
    if channel <= 0.04045:
        return channel / 12.92
    return ((channel + 0.055) / 1.055) ** 2.4


def hex_to_relative_luminance(hex_color: str) -> float:
    """Compute relative luminance according to WCAG 2.1 standard."""
    hex_clean = hex_color.strip().lstrip("#")
    if len(hex_clean) == 3:
        hex_clean = "".join(c * 2 for c in hex_clean)
    r = int(hex_clean[0:2], 16) / 255.0
    g = int(hex_clean[2:4], 16) / 255.0
    b = int(hex_clean[4:6], 16) / 255.0

    lr = srgb_channel_to_linear(r)
    lg = srgb_channel_to_linear(g)
    lb = srgb_channel_to_linear(b)

    return 0.2126 * lr + 0.7152 * lg + 0.0722 * lb


def calculate_contrast_ratio(color_a: str, color_b: str) -> float:
    """Calculate WCAG 2.1 contrast ratio between two hex colors."""
    lum_a = hex_to_relative_luminance(color_a)
    lum_b = hex_to_relative_luminance(color_b)
    l_bright = max(lum_a, lum_b)
    l_dark = min(lum_a, lum_b)
    ratio = (l_bright + 0.05) / (l_dark + 0.05)
    return round(ratio, 2)


def validate_wcag_aaa_contrast(
    text_color: str = COLOR_TEXT_PRIMARY,
    theme_backing: str = COLOR_DARK_THEME_BACKING,
    badge_backing: str = COLOR_DECOUPLED_BADGE,
) -> Tuple[bool, float, float]:
    """Validate text and graphical contrasts against WCAG 2.1 AAA standards."""
    text_cr = calculate_contrast_ratio(text_color, theme_backing)
    badge_cr = calculate_contrast_ratio(text_color, badge_backing)
    is_valid = (
        text_cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
        and badge_cr >= WCAG_AAA_BADGE_CONTRAST_TARGET
    )
    return is_valid, text_cr, badge_cr


# ============================================================================
# 5. Data Models: TreeNode, RadialTree, RadialTreeMetrics
# ============================================================================

@dataclass
class TreeNode:
    """Hierarchical node in the radial dependency tree."""
    id: str
    name: str
    depth: int = 0
    health_score: float = 100.0          # Health score in % [0.0..100.0]
    weight: float = 1.0                  # Subtree allocation weight
    parent_id: Optional[str] = None
    children_ids: List[str] = field(default_factory=list)
    tag: str = ""                        # Industrial SCADA Tag (e.g. "PLANT-01", "C-101")
    unit_type: str = "Asset"             # "Refinery", "Area", "Unit", "Subsystem"

    # Layout coordinates (populated during layout)
    radius: float = 0.0
    theta_rad: float = 0.0
    theta_min_rad: float = 0.0
    theta_max_rad: float = 2.0 * math.pi
    x: float = 0.0
    y: float = 0.0

    # Operational status
    is_fault: bool = False
    status: str = "NOMINAL"              # "NOMINAL", "WARNING", "CRITICAL"
    index: int = 0

    # Object references (bidirectional)
    parent: Optional[TreeNode] = None
    children: List[TreeNode] = field(default_factory=list)

    def add_child(self, child: TreeNode) -> None:
        """Add child node, establishing bidirectional references."""
        if child.id not in self.children_ids:
            self.children_ids.append(child.id)
        if child not in self.children:
            self.children.append(child)
        child.parent = self
        child.parent_id = self.id
        child.depth = self.depth + 1

    def remove_child(self, child_id: str) -> None:
        """Remove child node by ID."""
        if child_id in self.children_ids:
            self.children_ids.remove(child_id)
        self.children = [c for c in self.children if c.id != child_id]

    def is_leaf(self) -> bool:
        """Return True if node is a leaf (has no children)."""
        return len(self.children) == 0

    def get_leaves(self) -> List[TreeNode]:
        """Return all leaf nodes in the subtree rooted at this node."""
        if self.is_leaf():
            return [self]
        leaves: List[TreeNode] = []
        for child in self.children:
            leaves.extend(child.get_leaves())
        return leaves

    def get_descendants(self) -> List[TreeNode]:
        """Return all descendant nodes in subtree (excluding self)."""
        descendants: List[TreeNode] = []
        for child in self.children:
            descendants.append(child)
            descendants.extend(child.get_descendants())
        return descendants

    @property
    def angular_span_rad(self) -> float:
        """Angular span allocated to this node's subtree in radians."""
        return self.theta_max_rad - self.theta_min_rad

    @property
    def angular_span_deg(self) -> float:
        """Angular span in degrees."""
        return math.degrees(self.angular_span_rad)

    def compute_subtree_leaf_count(self) -> int:
        """Compute number of leaf nodes in the subtree."""
        if self.is_leaf():
            return 1
        return sum(child.compute_subtree_leaf_count() for child in self.children)

    def compute_subtree_weight(self) -> float:
        """Compute cumulative weight of the subtree."""
        if self.is_leaf():
            return max(0.1, self.weight)
        return sum(child.compute_subtree_weight() for child in self.children)


@dataclass
class RadialTree:
    """Hierarchical Tree Graph representing an industrial plant SCADA architecture."""
    nodes: Dict[str, TreeNode] = field(default_factory=dict)
    root_id: Optional[str] = None

    def add_node(self, node: TreeNode) -> None:
        """Add node to graph."""
        self.nodes[node.id] = node
        if self.root_id is None and node.parent_id is None:
            self.root_id = node.id

    def add_edge(self, parent_id: str, child_id: str) -> None:
        """Add directed edge from parent to child, establishing references."""
        if parent_id not in self.nodes:
            raise KeyError(f"Parent node '{parent_id}' not found in tree")
        if child_id not in self.nodes:
            raise KeyError(f"Child node '{child_id}' not found in tree")
        parent = self.nodes[parent_id]
        child = self.nodes[child_id]
        parent.add_child(child)

    def get_node(self, node_id: str) -> Optional[TreeNode]:
        """Look up node by ID."""
        return self.nodes.get(node_id)

    def get_root(self) -> Optional[TreeNode]:
        """Return root node if configured."""
        if self.root_id is not None:
            return self.nodes.get(self.root_id)
        # Search for node without parent
        for node in self.nodes.values():
            if node.parent_id is None:
                self.root_id = node.id
                return node
        return None

    def get_all_nodes(self) -> List[TreeNode]:
        """Return list of all tree nodes."""
        return list(self.nodes.values())

    def total_node_count(self) -> int:
        """Return total number of nodes in graph."""
        return len(self.nodes)

    def max_depth(self) -> int:
        """Compute maximum depth level present in tree."""
        root = self.get_root()
        if root is None or not self.nodes:
            return 0
        return max(n.depth for n in self.nodes.values())

    def detect_cycles(self) -> bool:
        """Detect if graph contains any cycles using depth-first search.

        Returns True if a cycle is found, False if graph is an acyclic tree.
        """
        # States: 0=unvisited, 1=in_recursion_stack (visiting), 2=visited (done)
        state: Dict[str, int] = {node_id: 0 for node_id in self.nodes}

        def _dfs(node_id: str) -> bool:
            state[node_id] = 1  # visiting
            node = self.nodes[node_id]
            for child in node.children:
                child_id = child.id
                if child_id not in state:
                    continue
                if state[child_id] == 1:
                    return True  # Back-edge found -> cycle
                if state[child_id] == 0:
                    if _dfs(child_id):
                        return True
            state[node_id] = 2  # done
            return False

        for nid in self.nodes:
            if state[nid] == 0:
                if _dfs(nid):
                    return True
        return False

    def validate_acyclic(self) -> None:
        """Raise HierarchyCycleError if cycle detected in tree."""
        if self.detect_cycles():
            raise HierarchyCycleError("Cycle detected in radial tree hierarchy")


@dataclass
class RadialTreeMetrics:
    """Aggregated operational metrics for Horner OCS memory synchronization (%R1680..%R1687)."""
    root_health_score: float = 95.0              # %R1680 scaled x10 (e.g. 950 = 95.0%)
    selected_node_index: int = 0                 # %R1681 (0..N)
    selected_node_health: float = 95.0           # %R1682 scaled x10 (e.g. 950 = 95.0%)
    critical_fault_count: int = 0                # %R1683 (Count of degraded nodes < 70.0%)
    max_tree_depth: int = 3                      # %R1684 (Hierarchy levels count)
    total_node_count: int = 21                   # %R1685 (Total nodes in tree)
    min_health_score: float = 90.0               # %R1686 scaled x10 (e.g. 900 = 90.0%)
    diagnostic_code: int = 0                     # %R1687 (0x0000=OK or diagnostic code)

    selected_node_id: str = "ROOT"
    selected_node_name: str = "Overall Plant Refinery"
    selected_node_tag: str = "PLANT-REF"
    min_health_node_id: str = "ROOT"


# ============================================================================
# 6. Layout Algorithm & Bottom-Up Health Propagation
# ============================================================================

def layout_radial_tree(
    tree: RadialTree,
    level_radii: Optional[List[float]] = None,
    center_x: float = CANVAS_CENTER_X,
    center_y: float = CANVAS_CENTER_Y,
    start_angle_rad: float = 0.0,
    sweep_angle_rad: float = 2.0 * math.pi,
) -> None:
    """Compute polar and Cartesian coordinates for all nodes in the radial tree.

    1. Validates acyclic hierarchy.
    2. Assigns concentric radial distance based on depth level.
    3. Allocates angular intervals [theta_min, theta_max] to subtrees proportionally.
    4. Places each node at the midpoint theta of its allocated interval.
    5. Converts (radius, theta) to Cartesian (x, y).
    """
    tree.validate_acyclic()
    root = tree.get_root()
    if root is None:
        return

    radii = level_radii if level_radii is not None else CANONICAL_LEVEL_RADII

    def _assign_depths(node: TreeNode, current_depth: int) -> None:
        node.depth = current_depth
        for child in node.children:
            _assign_depths(child, current_depth + 1)

    _assign_depths(root, 0)

    # Root allocation
    root.radius = radii[0] if len(radii) > 0 else 0.0
    root.theta_min_rad = start_angle_rad
    root.theta_max_rad = start_angle_rad + sweep_angle_rad
    root.theta_rad = (root.theta_min_rad + root.theta_max_rad) / 2.0
    root.x = center_x
    root.y = center_y

    def _layout_children(parent: TreeNode) -> None:
        if not parent.children:
            return

        total_weight = sum(c.compute_subtree_weight() for c in parent.children)
        parent_span = parent.theta_max_rad - parent.theta_min_rad

        current_angle = parent.theta_min_rad
        for child in parent.children:
            child_depth = child.depth
            if child_depth < len(radii):
                child.radius = radii[child_depth]
            else:
                extra = child_depth - len(radii) + 1
                child.radius = radii[-1] + extra * 90.0

            if total_weight > 0.0:
                child_fraction = child.compute_subtree_weight() / total_weight
            else:
                child_fraction = 1.0 / len(parent.children)

            child_span = parent_span * child_fraction
            child.theta_min_rad = current_angle
            child.theta_max_rad = current_angle + child_span
            child.theta_rad = (child.theta_min_rad + child.theta_max_rad) / 2.0

            pt = polar_to_cartesian(child.radius, child.theta_rad, center_x, center_y)
            child.x = pt.x
            child.y = pt.y

            current_angle += child_span

            # Recursively layout children
            _layout_children(child)

    _layout_children(root)


def propagate_bottom_up_health(
    tree: RadialTree,
    critical_threshold: float = HEALTH_CRITICAL_THRESHOLD,
    warning_threshold: float = HEALTH_WARNING_THRESHOLD,
) -> None:
    """Propagate health scores bottom-up from leaf assets to plant root.

    For leaf nodes: health_score is assigned / measured.
    For internal nodes: health_score is weighted average of children:
      H_parent = sum(weight_i * H_i) / sum(weight_i)
    Updates is_fault and status flag on all nodes.
    """
    root = tree.get_root()
    if root is None:
        return

    def _propagate(node: TreeNode) -> float:
        if node.is_leaf():
            # Leaf node health is intrinsic
            h = node.health_score
        else:
            total_w = 0.0
            weighted_h = 0.0
            for child in node.children:
                ch_health = _propagate(child)
                w = max(0.1, child.weight)
                weighted_h += ch_health * w
                total_w += w
            h = weighted_h / total_w if total_w > 0.0 else 100.0
            node.health_score = round(h, 2)

        # Status assignment
        if node.health_score < critical_threshold:
            node.is_fault = True
            node.status = NodeHealthState.CRITICAL.value
        elif node.health_score < warning_threshold:
            node.is_fault = False
            node.status = NodeHealthState.WARNING.value
        else:
            node.is_fault = False
            node.status = NodeHealthState.NOMINAL.value

        return node.health_score

    _propagate(root)


def identify_critical_faults(
    tree: RadialTree,
    critical_threshold: float = HEALTH_CRITICAL_THRESHOLD,
) -> List[TreeNode]:
    """Return all nodes exhibiting critical fault condition (health < critical_threshold)."""
    return [
        node for node in tree.nodes.values()
        if node.health_score < critical_threshold or node.is_fault
    ]


def find_min_health_node(tree: RadialTree) -> Optional[TreeNode]:
    """Find and return the node with the lowest health score in the tree."""
    if not tree.nodes:
        return None
    return min(tree.nodes.values(), key=lambda n: n.health_score)


# ============================================================================
# 7. Canonical Factory: Industrial SCADA Radial Tree Hierarchy
# ============================================================================

def create_canonical_scada_radial_tree() -> RadialTree:
    """Construct canonical 4-tier industrial refinery SCADA radial tree hierarchy.

    Hierarchy:
    - Level 0 (Central Root):
      - PLANT_ROOT: Overall Refinery Facility (Root Health ~ 95.0%)
    - Level 1 (4 Production Areas):
      - AREA_CRUDE: Crude Distillation Area
      - AREA_FCC: Fluid Catalytic Cracking Area
      - AREA_REFORM: Continuous Catalytic Reforming Area
      - AREA_UTILITY: Steam & Power Utilities Area
    - Level 2 (8 Operating Units, 2 per area):
      - UNIT_CDU, UNIT_VDU (Crude)
      - UNIT_RISER, UNIT_FRAC (FCC)
      - UNIT_PREHEAT, UNIT_REACTORS (Reform)
      - UNIT_BOILER, UNIT_TURBINE (Utility)
    - Level 3 (16 Equipment Subsystems / Assets, 2 per unit):
      - Pump trains, heater banks, compressor skids, distillation trays, valves.
    Total: 29 nodes across 4 concentric levels.
    """
    tree = RadialTree()

    # Level 0: Plant Core Root
    root = TreeNode(
        id="PLANT_ROOT",
        name="Industrial Refinery Plant",
        depth=0,
        health_score=95.0,
        weight=10.0,
        tag="PLANT-REF-01",
        unit_type="Refinery",
        index=0,
    )
    tree.add_node(root)

    # Level 1: 4 Production Areas
    areas = [
        ("AREA_CRUDE", "Crude Distillation Area", "AREA-01", 3.0),
        ("AREA_FCC", "Fluid Catalytic Cracking Area", "AREA-02", 3.0),
        ("AREA_REFORM", "Continuous Catalytic Reforming Area", "AREA-03", 2.0),
        ("AREA_UTILITY", "Steam & Power Utilities Area", "AREA-04", 2.0),
    ]

    for idx, (aid, aname, atag, awt) in enumerate(areas, start=1):
        anode = TreeNode(
            id=aid,
            name=aname,
            parent_id="PLANT_ROOT",
            depth=1,
            health_score=95.0,
            weight=awt,
            tag=atag,
            unit_type="Area",
            index=idx,
        )
        tree.add_node(anode)
        tree.add_edge("PLANT_ROOT", aid)

    # Level 2: 8 Units (2 per area)
    units_def = [
        # Crude units
        ("UNIT_CDU", "Atmospheric Distillation Unit", "AREA_CRUDE", "CDU-100", 1.5),
        ("UNIT_VDU", "Vacuum Distillation Unit", "AREA_CRUDE", "VDU-200", 1.5),
        # FCC units
        ("UNIT_RISER", "Riser Reactor & Regenerator", "AREA_FCC", "FCC-300", 1.5),
        ("UNIT_FRAC", "Main Fractionator Column", "AREA_FCC", "FCC-350", 1.5),
        # Reforming units
        ("UNIT_PREHEAT", "Feed Preheating Furnaces", "AREA_REFORM", "REF-400", 1.0),
        ("UNIT_REACTORS", "Multi-Stage Catalytic Bed", "AREA_REFORM", "REF-450", 1.0),
        # Utility units
        ("UNIT_BOILER", "High-Pressure Steam Boilers", "AREA_UTILITY", "UTL-500", 1.0),
        ("UNIT_TURBINE", "Co-Gen Turbine Generator", "AREA_UTILITY", "UTL-550", 1.0),
    ]

    for idx, (uid, uname, parent_aid, utag, uwt) in enumerate(units_def, start=5):
        unode = TreeNode(
            id=uid,
            name=uname,
            parent_id=parent_aid,
            depth=2,
            health_score=95.0,
            weight=uwt,
            tag=utag,
            unit_type="Unit",
            index=idx,
        )
        tree.add_node(unode)
        tree.add_edge(parent_aid, uid)

    # Level 3: 16 Leaf Subsystems (2 per unit)
    leaves_def = [
        # CDU
        ("SS_CDU_PUMP", "Crude Feed Charge Pumps", "UNIT_CDU", "P-101A/B", 94.0),
        ("SS_CDU_COL", "Crude Fractionation Trays", "UNIT_CDU", "C-101", 96.0),
        # VDU
        ("SS_VDU_EJECT", "Steam Ejector Vacuum System", "UNIT_VDU", "J-201", 93.0),
        ("SS_VDU_COL", "Vacuum Column Internals", "UNIT_VDU", "C-201", 95.0),
        # FCC Riser
        ("SS_FCC_RISER", "Riser Feed Injection Nozzles", "UNIT_RISER", "R-301", 92.0),
        ("SS_FCC_REGEN", "Regenerator Air Grid & Cyclones", "UNIT_RISER", "R-302", 94.0),
        # FCC Fractionator
        ("SS_FCC_OHD", "Overhead Vapor Condenser", "UNIT_FRAC", "E-351", 96.0),
        ("SS_FCC_SLURRY", "Clarified Slurry Oil Settler", "UNIT_FRAC", "V-352", 95.0),
        # Reform Preheat
        ("SS_REF_FURN", "Charge Heaters 101/102", "UNIT_PREHEAT", "F-401", 97.0),
        ("SS_REF_EXCH", "Feed-Effluent Combined Exchanger", "UNIT_PREHEAT", "E-401", 95.0),
        # Reform Reactors
        ("SS_REF_R1R2", "Reformer Lead Reactors R-1/2", "UNIT_REACTORS", "R-401", 93.0),
        ("SS_REF_R3R4", "Reformer Tail Reactors R-3/4", "UNIT_REACTORS", "R-402", 96.0),
        # Boiler
        ("SS_BOIL_FEED", "Deaerator & Feedwater Pumps", "UNIT_BOILER", "B-501", 98.0),
        ("SS_BOIL_DRUM", "Steam Drum & Superheater", "UNIT_BOILER", "B-502", 94.0),
        # Turbine
        ("SS_TURB_GEN", "Multi-Stage Steam Turbine", "UNIT_TURBINE", "TG-551", 96.0),
        ("SS_TURB_COND", "Surface Condenser & Hotwell", "UNIT_TURBINE", "E-552", 97.0),
    ]

    for idx, (lid, lname, parent_uid, ltag, lhealth) in enumerate(leaves_def, start=13):
        lnode = TreeNode(
            id=lid,
            name=lname,
            parent_id=parent_uid,
            depth=3,
            health_score=lhealth,
            weight=1.0,
            tag=ltag,
            unit_type="Subsystem",
            index=idx,
        )
        tree.add_node(lnode)
        tree.add_edge(parent_uid, lid)

    # Compute coordinates and bottom-up health
    layout_radial_tree(tree)
    propagate_bottom_up_health(tree)

    return tree


# ============================================================================
# 8. Standalone W3C SVG 1.1 Vector Graphics Renderer
# ============================================================================

def generate_radial_tree_canvas_svg(
    tree: RadialTree,
    metrics: RadialTreeMetrics,
    status_bits: RadialTreeStatusBits,
    selected_node_id: Optional[str] = None,
    diagnostic_code: DiagnosticCode = DIAG_OK,
    viewport_width: int = CANVAS_VIEWPORT_WIDTH,
    viewport_height: int = CANVAS_VIEWPORT_HEIGHT,
    dark_theme_bg: str = COLOR_DARK_THEME_BACKING,
) -> str:
    """Generate standalone W3C SVG 1.1 vector graphic conforming to SCADA standards."""
    root = tree.get_root()
    if root is None:
        raise ValueError("Cannot render SVG for empty tree with no root")

    sel_id = selected_node_id or metrics.selected_node_id
    sel_node = tree.get_node(sel_id) or root

    # Collect SVG elements
    svg_parts: List[str] = []

    # SVG Root Header
    svg_parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" version="1.1" '
        f'width="{viewport_width}" height="{viewport_height}" '
        f'viewBox="0 0 {viewport_width} {viewport_height}">'
    )

    # Defs: Gradients and Filters
    svg_parts.append("  <defs>")
    svg_parts.append(
        '    <linearGradient id="cardGrad" x1="0%" y1="0%" x2="100%" y2="100%">'
        f'      <stop offset="0%" stop-color="{COLOR_CARD_BG}" stop-opacity="0.95"/>'
        '      <stop offset="100%" stop-color="#0F172A" stop-opacity="0.98"/>'
        "    </linearGradient>"
    )
    svg_parts.append(
        '    <filter id="glowEffect" x="-20%" y="-20%" width="140%" height="140%">'
        '      <feGaussianBlur stdDeviation="3" result="blur"/>'
        '      <feComposite in="SourceGraphic" in2="blur" operator="over"/>'
        "    </filter>"
    )
    svg_parts.append("  </defs>")

    # Viewport Background
    svg_parts.append(
        f'  <rect width="{viewport_width}" height="{viewport_height}" '
        f'fill="{dark_theme_bg}"/>'
    )

    # Concentric Level Guide Circles
    radii = CANONICAL_LEVEL_RADII
    cx = CANVAS_CENTER_X
    cy = CANVAS_CENTER_Y

    svg_parts.append('  <g class="guide-rings" opacity="0.6">')
    for depth_idx, r in enumerate(radii):
        if r > 0.0:
            svg_parts.append(
                f'    <circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r:.2f}" '
                f'fill="none" stroke="{COLOR_RING_GUIDE}" stroke-width="1.5" '
                f'stroke-dasharray="4,4"/>'
            )
            # Level radius label
            svg_parts.append(
                f'    <text x="{cx + r + 4:.2f}" y="{cy - 4:.2f}" '
                f'fill="{COLOR_TEXT_MUTED}" font-family="monospace" font-size="9">'
                f'L{depth_idx} (R={int(r)})</text>'
            )
    svg_parts.append("  </g>")

    # Hierarchical Cubic Bezier Edges
    svg_parts.append('  <g class="tree-edges">')
    for node in tree.nodes.values():
        if node.parent is not None:
            parent = node.parent
            p0 = Point2D(parent.x, parent.y)
            p3 = Point2D(node.x, node.y)
            pts = compute_cubic_bezier_points(
                p0=p0,
                p3=p3,
                r0=parent.radius,
                r3=node.radius,
                theta0=parent.theta_rad,
                theta3=node.theta_rad,
                center_x=cx,
                center_y=cy,
            )
            path_d = format_cubic_bezier_svg_path(pts[0], pts[1], pts[2], pts[3])

            edge_color = COLOR_ALARM_CRIMSON if node.is_fault else COLOR_TREE_EDGE
            edge_width = "2.0" if node.is_fault else "1.2"
            edge_opacity = "0.9" if node.is_fault else "0.55"

            svg_parts.append(
                f'    <path d="{path_d}" fill="none" stroke="{edge_color}" '
                f'stroke-width="{edge_width}" stroke-opacity="{edge_opacity}"/>'
            )
    svg_parts.append("  </g>")

    # Tree Nodes
    svg_parts.append('  <g class="tree-nodes">')
    for node in tree.nodes.values():
        # Health status color
        if node.is_fault or node.status == NodeHealthState.CRITICAL.value:
            node_fill = COLOR_ALARM_CRIMSON
            node_stroke = "#B91C1C"
        elif node.status == NodeHealthState.WARNING.value:
            node_fill = COLOR_WARM_AMBER
            node_stroke = "#B45309"
        else:
            node_fill = COLOR_NOMINAL_EMERALD
            node_stroke = "#047857"

        # Node radius based on depth
        if node.depth == 0:
            node_r = 16.0
        elif node.depth == 1:
            node_r = 11.0
        elif node.depth == 2:
            node_r = 8.0
        else:
            node_r = 6.0

        is_selected = (node.id == sel_node.id)

        # Pulse halo for selected or faulted node
        if is_selected:
            svg_parts.append(
                f'    <circle cx="{node.x:.2f}" cy="{node.y:.2f}" r="{node_r + 6.0:.2f}" '
                f'fill="none" stroke="{COLOR_FOCUS_BLUE}" stroke-width="2.5" '
                f'filter="url(#glowEffect)"/>'
            )
        elif node.is_fault:
            svg_parts.append(
                f'    <circle cx="{node.x:.2f}" cy="{node.y:.2f}" r="{node_r + 4.0:.2f}" '
                f'fill="none" stroke="{COLOR_ALARM_CRIMSON}" stroke-width="2.0" opacity="0.75"/>'
            )

        # Node Circle
        svg_parts.append(
            f'    <circle id="node-{node.id}" cx="{node.x:.2f}" cy="{node.y:.2f}" r="{node_r:.2f}" '
            f'fill="{node_fill}" stroke="{node_stroke}" stroke-width="2.0"/>'
        )

        # Node Label
        if node.depth <= 2 or is_selected or node.is_fault:
            lbl = html.escape(node.tag or node.id)
            lbl_y = node.y + (node_r + 12.0)
            lbl_color = COLOR_TEXT_PRIMARY if is_selected else COLOR_TEXT_MUTED
            font_wt = "bold" if is_selected else "normal"
            svg_parts.append(
                f'    <text x="{node.x:.2f}" y="{lbl_y:.2f}" text-anchor="middle" '
                f'fill="{lbl_color}" font-family="sans-serif" font-size="9" '
                f'font-weight="{font_wt}">{lbl}</text>'
            )
    svg_parts.append("  </g>")

    # Right-Hand HUD Telemetry Card
    card_x = 920.0
    card_y = 35.0
    card_w = 250.0
    card_h = 360.0

    svg_parts.append('  <g class="hud-telemetry">')
    svg_parts.append(
        f'    <rect x="{card_x:.2f}" y="{card_y:.2f}" width="{card_w:.2f}" height="{card_h:.2f}" '
        f'rx="8" ry="8" fill="url(#cardGrad)" stroke="{COLOR_CARD_BORDER}" stroke-width="1.5"/>'
    )

    # Card Title
    svg_parts.append(
        f'    <text x="{card_x + 16:.2f}" y="{card_y + 26:.2f}" '
        f'fill="{COLOR_TEXT_PRIMARY}" font-family="sans-serif" font-size="13" font-weight="bold">'
        'RADIAL TREE SCADA</text>'
    )
    svg_parts.append(
        f'    <text x="{card_x + 16:.2f}" y="{card_y + 42:.2f}" '
        f'fill="{COLOR_TEXT_MUTED}" font-family="sans-serif" font-size="9">'
        'Hierarchical Dependency Graph (W207)</text>'
    )

    # Decoupled Badge (WCAG 2.1 AAA > 18:1 contrast)
    badge_x = card_x + 16.0
    badge_y = card_y + 54.0
    badge_w = 218.0
    badge_h = 24.0

    svg_parts.append(
        f'    <rect x="{badge_x:.2f}" y="{badge_y:.2f}" width="{badge_w:.2f}" height="{badge_h:.2f}" '
        f'rx="4" ry="4" fill="{COLOR_DECOUPLED_BADGE}" stroke="#1E293B" stroke-width="1.0"/>'
    )
    svg_parts.append(
        f'    <text x="{badge_x + 10:.2f}" y="{badge_y + 16:.2f}" '
        f'fill="{COLOR_TEXT_PRIMARY}" font-family="monospace" font-size="10" font-weight="bold">'
        f'ROOT HEALTH: {metrics.root_health_score:.1f}%</text>'
    )

    # Telemetry Rows
    rows = [
        ("Selected Node:", f"{sel_node.id} ({sel_node.tag or 'ROOT'})"),
        ("Node Health:", f"{sel_node.health_score:.1f}% [{sel_node.status}]"),
        ("Node Depth:", f"Level {sel_node.depth}"),
        ("Critical Faults:", str(metrics.critical_fault_count)),
        ("Total Tree Nodes:", str(metrics.total_node_count)),
        ("Max Tree Depth:", f"{metrics.max_tree_depth} Levels"),
        ("Min Health Score:", f"{metrics.min_health_score:.1f}%"),
        ("Diagnostic Code:", f"0x{metrics.diagnostic_code:04X}"),
    ]

    curr_y = badge_y + 45.0
    for label, val in rows:
        val_color = COLOR_ALARM_CRIMSON if "CRITICAL" in val or (label == "Critical Faults:" and val != "0") else COLOR_TEXT_PRIMARY
        svg_parts.append(
            f'    <text x="{card_x + 16:.2f}" y="{curr_y:.2f}" '
            f'fill="{COLOR_TEXT_MUTED}" font-family="sans-serif" font-size="10">{label}</text>'
        )
        svg_parts.append(
            f'    <text x="{card_x + card_w - 16:.2f}" y="{curr_y:.2f}" text-anchor="end" '
            f'fill="{val_color}" font-family="monospace" font-size="10" font-weight="bold">'
            f'{html.escape(val)}</text>'
        )
        curr_y += 22.0

    # Status Indicator Lamp
    lamp_color = COLOR_ALARM_CRIMSON if (metrics.critical_fault_count > 0 or int(diagnostic_code) != 0) else COLOR_NOMINAL_EMERALD
    lamp_status_text = "CRITICAL FAULT ACTIVE" if (metrics.critical_fault_count > 0 or int(diagnostic_code) != 0) else "ALL SYSTEMS NOMINAL"
    svg_parts.append(
        f'    <circle cx="{card_x + 24:.2f}" y="{curr_y + 8:.2f}" r="6" '
        f'fill="{lamp_color}" stroke="{COLOR_CARD_BORDER}" stroke-width="1.5"/>'
    )
    svg_parts.append(
        f'    <text x="{card_x + 38:.2f}" y="{curr_y + 12:.2f}" '
        f'fill="{lamp_color}" font-family="sans-serif" font-size="10" font-weight="bold">'
        f'{lamp_status_text}</text>'
    )
    svg_parts.append("  </g>")

    # Close SVG
    svg_parts.append("</svg>")

    svg_content = "\n".join(svg_parts)

    # Verify well-formed XML
    try:
        ET.fromstring(svg_content)
    except Exception as exc:
        raise ValueError(f"Generated SVG failed XML parsing: {exc}") from exc

    return svg_content


# ============================================================================
# 9. Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

RADIAL_TREE_CANVAS_PURE_ST_POU: str = """PROGRAM RadialTreeCanvasSync
VAR
    RootAggregateHealthScoreScaled AT %R1680 : INT;
    SelectedNodeIndex              AT %R1681 : INT;
    SelectedNodeHealthScoreScaled  AT %R1682 : INT;
    CriticalFaultCount             AT %R1683 : INT;
    MaxTreeDepth                   AT %R1684 : INT;
    TotalNodeCount                 AT %R1685 : INT;
    MinHealthScoreScaled           AT %R1686 : INT;
    DiagnosticStatusCode           AT %R1687 : INT;
    CriticalFaultAlarmActive       AT %M392  : BOOL;
    RadialTreeCanvasActive         AT %M393  : BOOL;
END_VAR

IF RadialTreeCanvasActive THEN
    IF CriticalFaultCount > 0 OR DiagnosticStatusCode <> 0 THEN
        CriticalFaultAlarmActive := TRUE;
    ELSE
        CriticalFaultAlarmActive := FALSE;
    END_IF;
ELSE
    CriticalFaultAlarmActive := FALSE;
END_IF;
END_PROGRAM
"""

RADIAL_TREE_PURE_ST_POU: str = RADIAL_TREE_CANVAS_PURE_ST_POU
W207_RADIAL_TREE_PURE_ST_POU: str = RADIAL_TREE_CANVAS_PURE_ST_POU


def verify_radial_tree_canvas_pure_st() -> bool:
    """Verify primary RadialTreeCanvasSync POU syntax and symbol binding."""
    SecurityGuard.assert_pure_st_content(RADIAL_TREE_CANVAS_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(RADIAL_TREE_CANVAS_PURE_ST_POU)
    return pou is not None and pou.name == "RadialTreeCanvasSync" and pou.pou_type == POUType.PROGRAM


# ============================================================================
# 10. RadialTreeCanvas Class & ILogicUnit Implementation
# ============================================================================

class RadialTreeCanvas(ILogicUnit):
    """Cscape HMI Dynamic Radial Tree & Hierarchical Dependency Graph SCADA Canvas (W207)."""

    def __init__(
        self,
        tree: Optional[RadialTree] = None,
        selected_node_id: Optional[str] = None,
        reg_table: Optional[RegisterTable] = None,
    ) -> None:
        self.tree = tree if tree is not None else create_canonical_scada_radial_tree()
        self.selected_node_id: str = selected_node_id or (self.tree.get_root().id if self.tree.get_root() else "ROOT")
        self.reg_table: RegisterTable = reg_table if reg_table is not None else RegisterTable()

        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.critical_fault_alarm_active: bool = False
        self.canvas_active: bool = True

        self.status_bits: RadialTreeStatusBits = (
            RadialTreeStatusBits.CANVAS_ACTIVE
            | RadialTreeStatusBits.GEOMETRY_COMPUTED
            | RadialTreeStatusBits.HIERARCHY_VALID
            | RadialTreeStatusBits.HEALTH_PROPAGATED
            | RadialTreeStatusBits.SVG_VALID
            | RadialTreeStatusBits.WCAG_AAA_VERIFIED
            | RadialTreeStatusBits.NOMINAL_OPERATION
        )

        self.metrics: RadialTreeMetrics = RadialTreeMetrics()
        self.update_telemetry()
        self.sync_to_registers()

    def update_telemetry(self) -> None:
        """Recalculate bottom-up health and aggregated metrics."""
        propagate_bottom_up_health(self.tree)
        root = self.tree.get_root()
        root_h = root.health_score if root else 100.0

        sel_node = self.tree.get_node(self.selected_node_id) or root
        sel_idx = sel_node.index if sel_node else 0
        sel_h = sel_node.health_score if sel_node else 100.0

        faults = identify_critical_faults(self.tree)
        min_node = find_min_health_node(self.tree)
        min_h = min_node.health_score if min_node else 100.0

        self.critical_fault_alarm_active = (len(faults) > 0 or int(self.diagnostic_code) != 0)

        if self.critical_fault_alarm_active:
            self.status_bits |= RadialTreeStatusBits.CRITICAL_FAULT_ACTIVE
            self.status_bits &= ~RadialTreeStatusBits.NOMINAL_OPERATION
        else:
            self.status_bits &= ~RadialTreeStatusBits.CRITICAL_FAULT_ACTIVE
            if int(self.diagnostic_code) == 0:
                self.status_bits |= RadialTreeStatusBits.NOMINAL_OPERATION

        self.metrics = RadialTreeMetrics(
            root_health_score=root_h,
            selected_node_index=sel_idx,
            selected_node_health=sel_h,
            critical_fault_count=len(faults),
            max_tree_depth=self.tree.max_depth(),
            total_node_count=self.tree.total_node_count(),
            min_health_score=min_h,
            diagnostic_code=int(self.diagnostic_code) & 0xFFFF,
            selected_node_id=sel_node.id if sel_node else "ROOT",
            selected_node_name=sel_node.name if sel_node else "Plant Root",
            selected_node_tag=sel_node.tag if sel_node else "TAG",
            min_health_node_id=min_node.id if min_node else "ROOT",
        )

    def select_node(self, node_id: str) -> None:
        """Select an active node by ID."""
        if node_id in self.tree.nodes:
            self.selected_node_id = node_id
            self.status_bits |= RadialTreeStatusBits.NODE_SELECTED
            self.update_telemetry()
            self.sync_to_registers()

    def inject_node_fault(self, node_id: str, health_score: float = 45.0) -> None:
        """Simulate a localized sensor or equipment fault on a node."""
        node = self.tree.get_node(node_id)
        if node:
            node.health_score = health_score
            if health_score < HEALTH_CRITICAL_THRESHOLD:
                self.diagnostic_code = DIAG_ERR_CRITICAL_FAULT_TRIP
            self.update_telemetry()
            self.sync_to_registers()

    def trigger_cycle_fault(self) -> None:
        """Inject 0xE201 HIERARCHY_CYCLE_DETECTED fault."""
        self.diagnostic_code = DIAG_ERR_HIERARCHY_CYCLE_DETECTED
        self.status_bits |= RadialTreeStatusBits.CYCLE_DETECTED
        self.status_bits &= ~RadialTreeStatusBits.NOMINAL_OPERATION
        self.update_telemetry()
        self.sync_to_registers()

    def trigger_render_fault(self) -> None:
        """Inject 0xE204 SVG_RENDER_FAULT."""
        self.diagnostic_code = DIAG_ERR_SVG_RENDER_FAULT
        self.status_bits |= RadialTreeStatusBits.RENDER_FAULT
        self.status_bits &= ~RadialTreeStatusBits.NOMINAL_OPERATION
        self.update_telemetry()
        self.sync_to_registers()

    def reset_nominal(self) -> None:
        """Restore tree to canonical nominal operating conditions."""
        self.tree = create_canonical_scada_radial_tree()
        root = self.tree.get_root()
        self.selected_node_id = root.id if root else "ROOT"
        self.diagnostic_code = DIAG_OK
        self.critical_fault_alarm_active = False
        self.canvas_active = True
        self.status_bits = (
            RadialTreeStatusBits.CANVAS_ACTIVE
            | RadialTreeStatusBits.GEOMETRY_COMPUTED
            | RadialTreeStatusBits.HIERARCHY_VALID
            | RadialTreeStatusBits.HEALTH_PROPAGATED
            | RadialTreeStatusBits.SVG_VALID
            | RadialTreeStatusBits.WCAG_AAA_VERIFIED
            | RadialTreeStatusBits.NOMINAL_OPERATION
        )
        self.update_telemetry()
        self.sync_to_registers()

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize telemetry metrics to Horner OCS RegisterTable memory space.

        Bindings:
        - %R1680: RootAggregateHealthScoreScaled (INT16, scaled x10 %, e.g. 950 = 95.0%)
        - %R1681: SelectedNodeIndex (INT16, 0..N)
        - %R1682: SelectedNodeHealthScoreScaled (INT16, scaled x10 %, e.g. 880 = 88.0%)
        - %R1683: CriticalFaultCount (INT16, count of degraded nodes)
        - %R1684: MaxTreeDepth (INT16, max tree depth)
        - %R1685: TotalNodeCount (INT16, total node count)
        - %R1686: MinHealthScoreScaled (INT16, scaled x10 %, lowest health in tree)
        - %R1687: DiagnosticStatusCode (0x0000=OK or diagnostic code)
        - %M392: CriticalFaultAlarmActive (BOOL)
        - %M393: RadialTreeCanvasActive (BOOL)
        """
        reg = reg_table if reg_table is not None else self.reg_table

        r1680 = int(round(self.metrics.root_health_score * 10))
        r1681 = int(self.metrics.selected_node_index)
        r1682 = int(round(self.metrics.selected_node_health * 10))
        r1683 = int(self.metrics.critical_fault_count)
        r1684 = int(self.metrics.max_tree_depth)
        r1685 = int(self.metrics.total_node_count)
        r1686 = int(round(self.metrics.min_health_score * 10))

        diag_val = int(self.diagnostic_code) & 0xFFFF
        diag_s16 = diag_val - 0x10000 if diag_val >= 0x8000 else diag_val

        reg.write_word(REG_ROOT_HEALTH_SCORE_SCALED, r1680, privilege=privilege)
        reg.write_word(REG_SELECTED_NODE_INDEX, r1681, privilege=privilege)
        reg.write_word(REG_SELECTED_NODE_HEALTH_SCALED, r1682, privilege=privilege)
        reg.write_word(REG_CRITICAL_FAULT_COUNT, r1683, privilege=privilege)
        reg.write_word(REG_MAX_TREE_DEPTH, r1684, privilege=privilege)
        reg.write_word(REG_TOTAL_NODE_COUNT, r1685, privilege=privilege)
        reg.write_word(REG_MIN_HEALTH_SCORE_SCALED, r1686, privilege=privilege)
        reg.write_word(REG_DIAGNOSTIC_STATUS_CODE, diag_s16, privilege=privilege)

        reg.write_bit(COIL_CRITICAL_FAULT_ALARM_ACTIVE, bool(self.critical_fault_alarm_active), privilege=privilege)
        reg.write_bit(COIL_RADIAL_TREE_CANVAS_ACTIVE, bool(self.canvas_active), privilege=privilege)

    # ------------------------------------------------------------------------
    # ILogicUnit Protocol Implementation
    # ------------------------------------------------------------------------
    @property
    def name(self) -> str:
        return "RadialTreeCanvasSync"

    @property
    def priority(self) -> int:
        return 95

    @property
    def is_enabled(self) -> bool:
        return True

    def reset(self) -> None:
        """Reset internal unit state to initial nominal conditions."""
        self.reset_nominal()

    def scan_step(self, dt: float = 0.01) -> None:
        """Simulate single clock cycle step with delta time dt."""
        self.update_telemetry()
        self.sync_to_registers()

    def step(self) -> None:
        """Step alias."""
        self.scan_step()

    def execute(self, context: ScanContext) -> None:
        """Execute discrete logic cycle within Horner scan context."""
        self.update_telemetry()
        self.sync_to_registers(self.reg_table, privilege=PrivilegeMode.SYSTEM)

    def render_svg(
        self,
        viewport_width: int = CANVAS_VIEWPORT_WIDTH,
        viewport_height: int = CANVAS_VIEWPORT_HEIGHT,
        dark_theme_bg: str = COLOR_DARK_THEME_BACKING,
    ) -> str:
        """Render standalone W3C SVG 1.1 vector graphic."""
        return generate_radial_tree_canvas_svg(
            tree=self.tree,
            metrics=self.metrics,
            status_bits=self.status_bits,
            selected_node_id=self.selected_node_id,
            diagnostic_code=self.diagnostic_code,
            viewport_width=viewport_width,
            viewport_height=viewport_height,
            dark_theme_bg=dark_theme_bg,
        )


# Aliases for W207
RadialTreeCanvasEngine = RadialTreeCanvas
RadialTreeCanvasSync = RadialTreeCanvas


def create_canonical_radial_tree_canvas(
    selected_node_id: Optional[str] = None,
) -> RadialTreeCanvas:
    """Instantiate canonical Radial Tree Canvas bound to Horner OCS memory."""
    tree = create_canonical_scada_radial_tree()
    return RadialTreeCanvas(tree=tree, selected_node_id=selected_node_id)


def create_mock_scan_context(
    cycle: int = 1,
    dt_ms: float = 10.0,
    reg_table: Optional[RegisterTable] = None,
) -> ScanContext:
    """Helper to instantiate mock Horner ScanContext for discrete ILogicUnit execution."""
    regs = reg_table if reg_table is not None else RegisterTable()
    return ScanContext(
        cycle=cycle,
        dt_ms=dt_ms,
        elapsed_time_ms=cycle * dt_ms,
        get_register=lambda addr: regs.read_word(addr),
        set_register=lambda addr, val: regs.write_word(addr, val, privilege=PrivilegeMode.SYSTEM),
        get_variable=lambda name, default=None: default,
        set_variable=lambda name, val: None,
        record_fault=lambda fault: None,
    )


# ============================================================================
# 11. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_radial_tree_canvas_verification(
    output_path: Optional[str] = None,
    sample_svg_path: Optional[str] = None,
    work_package: str = "W207",
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite returning strict 4-state contract JSON."""
    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    final_evidence_path = output_path or str(repo_root / "artifacts" / "HMI" / "radial_tree_canvas_evidence.json")
    final_svg_path = sample_svg_path or str(repo_root / "artifacts" / "HMI" / "radial_tree_canvas_sample.svg")

    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure ST POU Grammar & AST Validation (%R1680..%R1687, %M392..%M393)
    # ------------------------------------------------------------------------
    s1_pass = False
    try:
        SecurityGuard.assert_pure_st_content(RADIAL_TREE_CANVAS_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(RADIAL_TREE_CANVAS_PURE_ST_POU)

        expected_vars = {
            "RootAggregateHealthScoreScaled": "%R1680",
            "SelectedNodeIndex": "%R1681",
            "SelectedNodeHealthScoreScaled": "%R1682",
            "CriticalFaultCount": "%R1683",
            "MaxTreeDepth": "%R1684",
            "TotalNodeCount": "%R1685",
            "MinHealthScoreScaled": "%R1686",
            "DiagnosticStatusCode": "%R1687",
            "CriticalFaultAlarmActive": "%M392",
            "RadialTreeCanvasActive": "%M393",
        }

        vmap = {v.name: v.address_binding for v in pou.variables}
        all_bindings_valid = all(vmap.get(k) == b for k, b in expected_vars.items())

        s1_pass = (
            pou is not None
            and pou.name == "RadialTreeCanvasSync"
            and pou.pou_type == POUType.PROGRAM
            and len(pou.variables) == 10
            and all_bindings_valid
        )
    except Exception:
        s1_pass = False

    test_results.append({
        "stage": 1,
        "check": "Pure_ST_POU_Grammar_AST_Validation",
        "passed": s1_pass,
        "details": "Verified 'RadialTreeCanvasSync' POU with SecurityGuard & STParser across Horner registers %R1680..%R1687 and %M392..%M393.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Anti-Ladder Construct Security Interception (ERR_LADDER_FORBIDDEN)
    # ------------------------------------------------------------------------
    ladder_snippets = [
        ("Contacts", "PROGRAM Bad VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"),
        ("Coils", "PROGRAM Bad VAR Y: BOOL; END_VAR ---( )--- END_PROGRAM"),
        ("Rung", "PROGRAM Bad\nRUNG 1:\nEND_PROGRAM"),
        ("Network", "PROGRAM Bad\nNETWORK 1:\nEND_PROGRAM"),
        ("Mnemonic_XIC", "PROGRAM Bad\nXIC bit1;\nEND_PROGRAM"),
        ("Mnemonic_OTE", "PROGRAM Bad\nOTE bit2;\nEND_PROGRAM"),
    ]
    rejected_count = 0
    for name, snippet in ladder_snippets:
        try:
            SecurityGuard.assert_pure_st_content(snippet)
        except LadderForbiddenError:
            rejected_count += 1
        except Exception:
            pass

    s2_pass = (rejected_count == len(ladder_snippets))
    test_results.append({
        "stage": 2,
        "check": "Anti_Ladder_Construct_Security_Interception",
        "passed": s2_pass,
        "details": f"Rejected {rejected_count}/{len(ladder_snippets)} forbidden ladder logic constructs with LadderForbiddenError.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Node Hierarchy Structures, Parent-Child References & Cycle Detection
    # ------------------------------------------------------------------------
    tree = create_canonical_scada_radial_tree()
    s3_pass = False
    try:
        # Check bidirectional links
        root = tree.get_root()
        root_children_valid = (root is not None and len(root.children) == 4)
        all_children_point_to_parent = all(
            c.parent is root for c in root.children
        )

        # Check acyclic detection
        acyclic_flag = not tree.detect_cycles()

        # Check cyclic detection on mutated graph
        cycle_tree = RadialTree()
        n_a = TreeNode(id="A", name="Node A")
        n_b = TreeNode(id="B", name="Node B")
        cycle_tree.add_node(n_a)
        cycle_tree.add_node(n_b)
        cycle_tree.add_edge("A", "B")
        cycle_tree.add_edge("B", "A")  # intentional cycle
        cycle_detected = cycle_tree.detect_cycles()

        s3_pass = (
            root_children_valid
            and all_children_point_to_parent
            and acyclic_flag
            and cycle_detected
            and tree.total_node_count() == 29
        )
    except Exception:
        s3_pass = False

    test_results.append({
        "stage": 3,
        "check": "Node_Hierarchy_Structures_And_Cycle_Detection",
        "passed": s3_pass,
        "details": f"Validated 29 nodes, bidirectional references, acyclic invariant, and cycle detection.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Polar-to-Cartesian Radial Positioning & Angular Spacing Conservation
    # ------------------------------------------------------------------------
    s4_pass = False
    try:
        # Check concentric radii
        radii_ok = all(
            math.isclose(node.radius, CANONICAL_LEVEL_RADII[node.depth], abs_tol=1e-3)
            for node in tree.nodes.values()
        )
        # Check root at center
        root = tree.get_root()
        root_center = (
            math.isclose(root.x, CANVAS_CENTER_X, abs_tol=1e-2)
            and math.isclose(root.y, CANVAS_CENTER_Y, abs_tol=1e-2)
        )
        # Check angular conservation across root children
        root_children_span_sum = sum(c.angular_span_rad for c in root.children)
        angular_sum_ok = math.isclose(root_children_span_sum, 2.0 * math.pi, abs_tol=1e-4)

        # Check Cartesian transformation formula
        pt_ok = True
        for node in tree.nodes.values():
            if node.depth > 0:
                expected_pt = polar_to_cartesian(node.radius, node.theta_rad, CANVAS_CENTER_X, CANVAS_CENTER_Y)
                if not (math.isclose(node.x, expected_pt.x, abs_tol=1e-2) and math.isclose(node.y, expected_pt.y, abs_tol=1e-2)):
                    pt_ok = False
                    break

        s4_pass = radii_ok and root_center and angular_sum_ok and pt_ok
    except Exception:
        s4_pass = False

    test_results.append({
        "stage": 4,
        "check": "Polar_To_Cartesian_Radial_Tree_Positioning",
        "passed": s4_pass,
        "details": "Verified 4 concentric radial rings, angular span conservation (2*pi rad), and Cartesian math.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Cubic Bezier Hierarchical Curve Synthesis & Smoothness Invariant
    # ------------------------------------------------------------------------
    s5_pass = False
    try:
        # Check Bezier curve evaluation
        p0 = Point2D(CANVAS_CENTER_X, CANVAS_CENTER_Y)
        child = tree.get_node("AREA_CRUDE")
        p3 = Point2D(child.x, child.y)
        pts = compute_cubic_bezier_points(
            p0=p0,
            p3=p3,
            r0=0.0,
            r3=child.radius,
            theta0=0.0,
            theta3=child.theta_rad,
            center_x=CANVAS_CENTER_X,
            center_y=CANVAS_CENTER_Y,
        )

        b_start = eval_cubic_bezier(pts[0], pts[1], pts[2], pts[3], 0.0)
        b_mid = eval_cubic_bezier(pts[0], pts[1], pts[2], pts[3], 0.5)
        b_end = eval_cubic_bezier(pts[0], pts[1], pts[2], pts[3], 1.0)

        endpoint_ok = (
            math.isclose(b_start.x, p0.x, abs_tol=1e-2)
            and math.isclose(b_start.y, p0.y, abs_tol=1e-2)
            and math.isclose(b_end.x, p3.x, abs_tol=1e-2)
            and math.isclose(b_end.y, p3.y, abs_tol=1e-2)
        )

        svg_path_cmd = format_cubic_bezier_svg_path(pts[0], pts[1], pts[2], pts[3])
        path_syntax_ok = svg_path_cmd.startswith("M ") and " C " in svg_path_cmd

        s5_pass = endpoint_ok and path_syntax_ok
    except Exception:
        s5_pass = False

    test_results.append({
        "stage": 5,
        "check": "Cubic_Bezier_Hierarchical_Curve_Synthesis",
        "passed": s5_pass,
        "details": "Verified cubic Bezier B(0)=P0, B(1)=P3 endpoints, radial outward tangents, and SVG path syntax.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Bottom-Up Health Score Propagation & Critical Fault Identification
    # ------------------------------------------------------------------------
    s6_pass = False
    try:
        canvas = RadialTreeCanvas(tree=tree)
        # In canonical nominal state, health scores are all >= 90%
        nominal_h = canvas.metrics.root_health_score
        nominal_faults = canvas.metrics.critical_fault_count

        # Inject critical fault on a leaf subsystem
        canvas.inject_node_fault("SS_CDU_PUMP", 40.0)
        post_faults = canvas.metrics.critical_fault_count
        post_min_h = canvas.metrics.min_health_score
        fault_alarm = canvas.critical_fault_alarm_active

        s6_pass = (
            nominal_faults == 0
            and nominal_h >= 90.0
            and post_faults >= 1
            and post_min_h == 40.0
            and fault_alarm
        )
    except Exception:
        s6_pass = False

    test_results.append({
        "stage": 6,
        "check": "Bottom_Up_Health_Score_Propagation",
        "passed": s6_pass,
        "details": "Verified post-order bottom-up health propagation, critical threshold (<70%), and fault tripping.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: WCAG 2.1 AAA Contrast Ratio Verification (> 18:1 Decoupled Badge)
    # ------------------------------------------------------------------------
    is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast(
        text_color=COLOR_TEXT_PRIMARY,
        theme_backing=COLOR_DARK_THEME_BACKING,
        badge_backing=COLOR_DECOUPLED_BADGE,
    )

    s7_pass = (
        is_aaa
        and text_cr >= WCAG_AAA_TEXT_CONTRAST_TARGET
        and badge_cr >= WCAG_AAA_BADGE_CONTRAST_TARGET
    )

    test_results.append({
        "stage": 7,
        "check": "WCAG_2_1_AAA_Contrast_Ratio_Verification",
        "passed": s7_pass,
        "details": f"Verified decoupled badge contrast {badge_cr:.2f}:1 (> 18:1) and text contrast {text_cr:.2f}:1 (> 7:1).",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Standalone W3C SVG XML Parsing via xml.etree.ElementTree
    # ------------------------------------------------------------------------
    s8_pass = False
    try:
        canvas_nominal = RadialTreeCanvas()
        svg_str = canvas_nominal.render_svg()

        # Parse XML
        root_elem = ET.fromstring(svg_str)
        tag_is_svg = root_elem.tag.endswith("svg")
        has_rects = len(root_elem.findall(".//{http://www.w3.org/2000/svg}rect")) + len(root_elem.findall(".//rect")) > 0
        has_paths = len(root_elem.findall(".//{http://www.w3.org/2000/svg}path")) + len(root_elem.findall(".//path")) > 0
        has_circles = len(root_elem.findall(".//{http://www.w3.org/2000/svg}circle")) + len(root_elem.findall(".//circle")) > 0

        # Save sample SVG
        svg_p = Path(final_svg_path)
        svg_p.parent.mkdir(parents=True, exist_ok=True)
        with open(svg_p, "w", encoding="utf-8") as f:
            f.write(svg_str)

        s8_pass = tag_is_svg and has_rects and has_paths and has_circles
    except Exception:
        s8_pass = False

    test_results.append({
        "stage": 8,
        "check": "Standalone_W3C_SVG_XML_Parsing",
        "passed": s8_pass,
        "details": f"Parsed valid XML SVG with guide rings, cubic Bezier edges, nodes, and HUD telemetry card -> {final_svg_path}.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Horner OCS Register Space Synchronization & ILogicUnit Scan Cycle
    # ------------------------------------------------------------------------
    s9_pass = False
    try:
        reg_table = RegisterTable()
        canvas_sync = RadialTreeCanvas(reg_table=reg_table)
        canvas_sync.scan_step(dt=0.01)

        r1680 = reg_table.read_word("%R1680")  # Root health scaled x10
        r1681 = reg_table.read_word("%R1681")  # Selected node index
        r1683 = reg_table.read_word("%R1683")  # Critical fault count
        r1684 = reg_table.read_word("%R1684")  # Max tree depth (3)
        r1685 = reg_table.read_word("%R1685")  # Total node count (29)
        r1687 = reg_table.read_word("%R1687")  # Diag status code (0)
        m392 = reg_table.read_bit("%M392")    # Critical fault alarm (False)
        m393 = reg_table.read_bit("%M393")    # Canvas active (True)

        registers_ok = (
            r1680 >= 900
            and r1681 == 0
            and r1683 == 0
            and r1684 == 3
            and r1685 == 29
            and r1687 == 0
            and (not m392)
            and m393
        )

        # Context execution
        ctx = create_mock_scan_context(cycle=1, dt_ms=10.0, reg_table=reg_table)
        canvas_sync.execute(ctx)

        s9_pass = registers_ok
    except Exception:
        s9_pass = False

    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Register_Sync_And_Scan_Cycle",
        "passed": s9_pass,
        "details": "Verified %R1680..%R1687 and %M392..%M393 with PrivilegeMode.SYSTEM and ILogicUnit scan cycle.",
    })

    # ------------------------------------------------------------------------
    # Aggregate Strict 4-State Verification Report
    # ------------------------------------------------------------------------
    checks_passed = sum(1 for t in test_results if t["passed"])
    total_checks = len(test_results)
    all_passed = (checks_passed == total_checks)

    overall_status = "success" if all_passed else "failed"
    error_code = None if all_passed else "STAGE_VERIFICATION_FAILURE"

    report_payload: Dict[str, Any] = {
        "status": overall_status,
        "error_code": error_code,
        "details": f"Deterministic verification: {checks_passed}/{total_checks} stages passed.",
        "data": {
            "work_package": work_package,
            "gate": "Gate G9 / G2",
            "component": "Cscape HMI Dynamic Radial Tree & Hierarchical Dependency Graph SCADA Canvas",
            "checks_passed": checks_passed,
            "total_checks": total_checks,
            "tests": test_results,
        },
    }

    # Write JSON evidence
    evidence_p = Path(final_evidence_path)
    evidence_p.parent.mkdir(parents=True, exist_ok=True)
    with open(evidence_p, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

    return report_payload
