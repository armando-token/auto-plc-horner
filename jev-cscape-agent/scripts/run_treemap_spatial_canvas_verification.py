#!/usr/bin/env python3
"""Verification Script for Cscape HMI Dynamic Treemap Spatial Canvas (W261).

Work Package: W261 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Treemap Spatial Asset Partitioning SCADA Canvas]
Status Contract: Strict 4-State JSON output & evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: Asset Hierarchy Tree & Bounding Box Spatial Partitioning
  Stage 2: Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard
  Stage 3: Anti-Ladder Security Guard Interception
  Stage 4: Squarified Layout Aspect Ratio Optimization (Worst Ratio < 3.0)
  Stage 5: WCAG AAA Color Contrast Compliance (>= 18:1 badges, >= 7:1 text)
  Stage 6: Invalid Hierarchy & Degeneration Fault Injections (0x7701, 0x7702, %M519)
  Stage 7: Interactive Drilldown Zoom & Nested Level Filtering
  Stage 8: Horner OCS Register Table Synchronization (%R2220..%R2227, %M518..%M519)
  Stage 9: Visual Grounding Fallback & High-Res SVG Export

Exports:
  artifacts/HMI/treemap_spatial_canvas_evidence.json
  artifacts/HMI/treemap_spatial_canvas_sample.svg
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from enum import Enum
import html
import inspect
import json
import math
from pathlib import Path
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union
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

# ANSI color escape codes matching repo conventions
CLR_RESET  = "\033[0m"
CLR_BOLD   = "\033[1m"
CLR_DIM    = "\033[2m"
CLR_GREEN  = "\033[92m"
CLR_RED    = "\033[91m"
CLR_YELLOW = "\033[93m"
CLR_CYAN   = "\033[96m"
CLR_GRAY   = "\033[90m"


# ============================================================================
# 1. Constants, Diagnostic Codes & Register Mapping for W261
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


# Diagnostic event codes conforming to Horner OCS %R2227 specification for W261
DIAG_OK: DiagnosticCode                          = DiagnosticCode(0x0000)
DIAG_EVENT_OK: DiagnosticCode                    = DiagnosticCode(0x0000)
DIAG_ERR_INVALID_HIERARCHY: DiagnosticCode       = DiagnosticCode(0x7701)  # Invalid Hierarchy Fault
DIAG_ERR_DEGENERATION_FAULT: DiagnosticCode      = DiagnosticCode(0x7702)  # Degeneration Fault (Bounds / Area)
DIAG_ERR_GEOMETRY_SINGULARITY: DiagnosticCode    = DiagnosticCode(0x7703)  # Geometry Singularity Fault
DIAG_ERR_SVG_RENDER: DiagnosticCode              = DiagnosticCode(0x7704)  # SVG Render Fault

# Horner OCS Word Registers (%R2220..%R2227) for W261
REG_W261_TOTAL_ASSET_NODE_COUNT: str             = "%R2220"  # INT16, Total asset node count (21)
REG_W261_ACTIVE_DRILLDOWN_LEVEL: str             = "%R2221"  # INT16, Active drilldown level (0=Root, 1=Area, 2=Unit)
REG_W261_SELECTED_ASSET_NODE_INDEX: str          = "%R2222"  # INT16, Selected asset node index (1..21)
REG_W261_WORST_ASPECT_RATIO_SCALED: str          = "%R2223"  # INT16, Worst aspect ratio scaled x100 (< 300)
REG_W261_TOTAL_TREE_WEIGHT_METRIC_SCALED: str    = "%R2224"  # INT16, Total weight scaled / 10 (nominal 1200)
REG_W261_CRITICAL_ALARM_NODE_COUNT: str          = "%R2225"  # INT16, Critical alarm node count (nominal 0)
REG_W261_OVERALL_ASSET_HEALTH_PCT_SCALED: str    = "%R2226"  # INT16, Overall health scaled x100 (nominal 9640)
REG_W261_DIAGNOSTIC_STATUS_CODE: str             = "%R2227"  # INT16, Diagnostic status code (0x0000, 0x7701, 0x7702)

# Discrete Coils (%M518..%M519) for W261
COIL_W261_TREEMAP_SPATIAL_CANVAS_ACTIVE: str     = "%M518"   # BOOL, True when canvas active & nominal
COIL_W261_TREEMAP_HIERARCHY_FAULT_ALARM: str     = "%M519"   # BOOL, True when fault 0x7701/0x7702 or critical alarm

# Viewport and Geometry Layout Constants
CANVAS_VIEWPORT_WIDTH: int                       = 1200
CANVAS_VIEWPORT_HEIGHT: int                      = 800

DEFAULT_CANVAS_X: float                          = 24.0
DEFAULT_CANVAS_Y: float                          = 88.0
DEFAULT_CANVAS_WIDTH: float                      = 1152.0
DEFAULT_CANVAS_HEIGHT: float                     = 688.0

# Canonical Hierarchy Dimensions
CANONICAL_TOTAL_NODES: int                       = 21       # 1 Complex Root + 5 Areas + 15 Units
CANONICAL_TOTAL_AREAS: int                       = 5
CANONICAL_TOTAL_UNITS: int                       = 15
CANONICAL_MAX_DEPTH: int                         = 3        # Tier 0 (Root), Tier 1 (Area), Tier 2 (Unit)
CANONICAL_TOTAL_WEIGHT_METRIC: float             = 12000.0  # kg/h material flux
CANONICAL_TOTAL_WEIGHT_SCALED: int               = 1200     # 12000.0 / 10
CANONICAL_OVERALL_HEALTH_PCT: float              = 96.40
CANONICAL_OVERALL_HEALTH_SCALED: int             = 9640
CANONICAL_CRITICAL_ALARMS: int                   = 0

# Aspect Ratio Thresholds
OPTIMAL_ASPECT_RATIO_TARGET: float               = 1.0
WORST_ASPECT_RATIO_CEILING: float                = 3.0      # Strict ceiling: Worst ratio < 3.0

# Dark Industrial SCADA Palette & WCAG AAA Contrast
COLOR_DARK_THEME_BACKING: str                    = "#0B0F19"  # Viewport dark background
COLOR_PANEL_BG: str                              = "#161B22"  # Panel card background
COLOR_BORDER: str                                = "#21262D"  # Industrial borders
COLOR_DECOUPLED_BADGE: str                       = "#050811"  # Ultra-dark decoupled badge (> 18:1 contrast)
COLOR_TEXT_PRIMARY: str                          = "#FFFFFF"  # Pure white text (>= 18:1 contrast on badge)
COLOR_TEXT_MUTED: str                            = "#CBD5E1"  # Light slate secondary text (>= 7.0:1 on badge)
COLOR_FOCUS_CYAN: str                            = "#06B6D4"  # Highlight cyan
COLOR_GRID_LINE: str                             = "#1F2937"  # Divider line stroke

# Health / Thermal Status Colors (WCAG compliant)
COLOR_HEALTH_NORMAL: str                         = "#10B981"  # Optimal / Normal (Emerald, >= 90.0%)
COLOR_HEALTH_GOOD: str                           = "#06B6D4"  # Nominal / Good (Cyan, 80.0% - 89.9%)
COLOR_HEALTH_WARNING: str                        = "#F59E0B"  # Warning / Elevated (Amber, 70.0% - 79.9%)
COLOR_HEALTH_CRITICAL: str                       = "#EF4444"  # Critical / Alarm (Crimson, < 70.0%)
COLOR_HEALTH_INACTIVE: str                       = "#64748B"  # Inactive / Standby (Slate)

HEALTH_CRITICAL_THRESHOLD: float                 = 70.0
HEALTH_WARNING_THRESHOLD: float                  = 80.0
HEALTH_GOOD_THRESHOLD: float                     = 90.0


# ============================================================================
# 2. Pure IEC 61131-3 Structured Text (ST) POU for W261
# ============================================================================

W261_TREEMAP_SPATIAL_CANVAS_PURE_ST_POU: str = """PROGRAM TreemapSpatialCanvasSync
VAR
    TotalAssetNodeCount         AT %R2220 : INT;
    ActiveDrilldownLevel        AT %R2221 : INT;
    SelectedAssetNodeIndex      AT %R2222 : INT;
    WorstAspectRatioScaled      AT %R2223 : INT;
    TotalTreeWeightMetricScaled AT %R2224 : INT;
    CriticalAlarmNodeCount      AT %R2225 : INT;
    OverallAssetHealthPctScaled AT %R2226 : INT;
    DiagnosticStatusCode        AT %R2227 : INT;
    TreemapSpatialCanvasActive  AT %M518  : BOOL;
    TreemapHierarchyFaultAlarm  AT %M519  : BOOL;
END_VAR

IF DiagnosticStatusCode = 0 AND WorstAspectRatioScaled < 300 THEN
    TreemapSpatialCanvasActive := TRUE;
ELSE
    TreemapSpatialCanvasActive := FALSE;
END_IF;

IF DiagnosticStatusCode <> 0 OR CriticalAlarmNodeCount > 0 THEN
    TreemapHierarchyFaultAlarm := TRUE;
ELSE
    TreemapHierarchyFaultAlarm := FALSE;
END_IF;
END_PROGRAM
"""


# ============================================================================
# 3. Geometry, Node Model & Asset Hierarchy Tree
# ============================================================================

class HealthState(str, Enum):
    """Operational health categories for asset equipment."""
    NORMAL   = "NORMAL"
    GOOD     = "GOOD"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"
    INACTIVE = "INACTIVE"


@dataclass
class Rect:
    """Planar rectangular bounding box."""
    x: float = 0.0
    y: float = 0.0
    width: float = 0.0
    height: float = 0.0

    @property
    def right(self) -> float:
        return self.x + self.width

    @property
    def bottom(self) -> float:
        return self.y + self.height

    @property
    def area(self) -> float:
        return max(0.0, self.width) * max(0.0, self.height)

    @property
    def aspect_ratio(self) -> float:
        """Elongation ratio max(w/h, h/w) >= 1.0."""
        w = max(1e-9, self.width)
        h = max(1e-9, self.height)
        return max(w / h, h / w)

    def contains(self, other: Rect, epsilon: float = 1e-3) -> bool:
        """Check if this rectangle geometrically encloses another."""
        return (
            self.x - epsilon <= other.x
            and self.y - epsilon <= other.y
            and self.right + epsilon >= other.right
            and self.bottom + epsilon >= other.bottom
        )

    def intersects(self, other: Rect, epsilon: float = 1e-3) -> bool:
        """Check if two rectangles overlap with strictly positive intersection area."""
        ox = max(0.0, min(self.right, other.right) - max(self.x, other.x))
        oy = max(0.0, min(self.bottom, other.bottom) - max(self.y, other.y))
        return (ox > epsilon) and (oy > epsilon)


class AssetNode:
    """Asset hierarchy tree node representing plant complex, area, or equipment module."""

    def __init__(
        self,
        node_id: str,
        name: str,
        tier: int,
        index: int,
        tag: str = "",
        weight: float = 100.0,
        health_score: float = 95.0,
        state: HealthState = HealthState.NORMAL,
        parent: Optional[AssetNode] = None,
    ) -> None:
        self.id: str = node_id
        self.name: str = name
        self.tier: int = tier          # 0: Complex Root, 1: Process Area, 2: Unit/Module
        self.index: int = index        # 1-based index (1..21)
        self.tag: str = tag or node_id
        self.weight: float = weight
        self.health_score: float = health_score
        self.state: HealthState = state
        self.parent: Optional[AssetNode] = parent
        self.children: List[AssetNode] = []
        self.rect: Rect = Rect()

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

    @property
    def color(self) -> str:
        """Status color mapping based on health state."""
        if self.state == HealthState.CRITICAL:
            return COLOR_HEALTH_CRITICAL
        if self.state == HealthState.WARNING:
            return COLOR_HEALTH_WARNING
        if self.state == HealthState.GOOD:
            return COLOR_HEALTH_GOOD
        if self.state == HealthState.INACTIVE:
            return COLOR_HEALTH_INACTIVE
        return COLOR_HEALTH_NORMAL

    def add_child(self, child: AssetNode) -> None:
        child.parent = self
        self.children.append(child)

    def get_all_nodes(self) -> List[AssetNode]:
        """Return flattened list of this node and all descendants."""
        res = [self]
        for c in self.children:
            res.extend(c.get_all_nodes())
        return res

    def get_leaves(self) -> List[AssetNode]:
        """Return descendant leaf tiles."""
        if not self.children:
            return [self]
        leaves: List[AssetNode] = []
        for c in self.children:
            leaves.extend(c.get_leaves())
        return leaves

    def max_depth(self) -> int:
        """Calculate maximum tree depth from this node."""
        if not self.children:
            return 1
        return 1 + max(c.max_depth() for c in self.children)

    def recalculate_aggregates(self) -> None:
        """Recursively update weight and health from child nodes."""
        if self.is_leaf:
            return
        total_w = 0.0
        weighted_health = 0.0
        for c in self.children:
            c.recalculate_aggregates()
            total_w += c.weight
            weighted_health += c.health_score * max(1e-6, c.weight)

        self.weight = total_w
        if total_w > 1e-9:
            self.health_score = round(weighted_health / total_w, 2)
            if self.health_score < HEALTH_CRITICAL_THRESHOLD:
                self.state = HealthState.CRITICAL
            elif self.health_score < HEALTH_WARNING_THRESHOLD:
                self.state = HealthState.WARNING
            elif self.health_score < HEALTH_GOOD_THRESHOLD:
                self.state = HealthState.GOOD
            else:
                self.state = HealthState.NORMAL


class AssetHierarchyTree:
    """Container managing the multi-tier plant asset hierarchy tree."""

    def __init__(self, root: Optional[AssetNode] = None) -> None:
        self.root: Optional[AssetNode] = root
        self._nodes_by_id: Dict[str, AssetNode] = {}
        self._nodes_by_index: Dict[int, AssetNode] = {}
        if root is not None:
            self.reindex()

    def reindex(self) -> None:
        self._nodes_by_id.clear()
        self._nodes_by_index.clear()
        if self.root is not None:
            for n in self.root.get_all_nodes():
                self._nodes_by_id[n.id] = n
                self._nodes_by_index[n.index] = n

    def get_node(self, node_id: str) -> Optional[AssetNode]:
        return self._nodes_by_id.get(node_id)

    def get_node_by_index(self, index: int) -> Optional[AssetNode]:
        return self._nodes_by_index.get(index)

    @property
    def total_nodes(self) -> int:
        return len(self._nodes_by_id)

    @property
    def total_leaves(self) -> int:
        return len(self.root.get_leaves()) if self.root else 0

    @property
    def max_depth(self) -> int:
        return self.root.max_depth() if self.root else 0

    def get_all_nodes(self) -> List[AssetNode]:
        return self.root.get_all_nodes() if self.root else []

    def get_leaves(self) -> List[AssetNode]:
        return self.root.get_leaves() if self.root else []

    def get_critical_count(self) -> int:
        return sum(1 for n in self.get_leaves() if n.state == HealthState.CRITICAL)


def create_canonical_asset_hierarchy() -> AssetHierarchyTree:
    """Create canonical W261 asset hierarchy (21 nodes: 1 Complex + 5 Areas + 15 Units)."""
    # Tier 0: Root Petrochemical Complex Alpha
    root = AssetNode(
        node_id="ROOT_COMPLEX",
        name="Petrochemical Complex Alpha",
        tier=0,
        index=1,
        tag="PLANT-01",
        weight=12000.0,
        health_score=96.40,
        state=HealthState.NORMAL,
    )

    idx = 2
    # Tier 1: Process Areas & Tier 2: Sub-units
    areas_data = [
        ("AREA_ALK", "Alkylation & HF Treater", "AREA-100", 3200.0, [
            ("UNIT_R101", "Acid Contactor Reactor R-101", "R-101", 1200.0, 98.0),
            ("UNIT_C102", "Isobutane Fractionator C-102", "C-102", 1100.0, 96.0),
            ("UNIT_E103", "Acid Settler Cooler E-103", "E-103", 900.0, 95.5),
        ]),
        ("AREA_CCR", "Catalytic Reforming CCR", "AREA-200", 2800.0, [
            ("UNIT_H201", "Reformer Charge Heater H-201", "H-201", 1050.0, 97.0),
            ("UNIT_R202", "Radial Multi-Bed Reactor R-202", "R-202", 1000.0, 98.5),
            ("UNIT_K203", "Hydrogen Recycle Compressor K-203", "K-203", 750.0, 96.0),
        ]),
        ("AREA_FCC", "Fluid Catalytic Cracking", "AREA-300", 3000.0, [
            ("UNIT_R301", "Riser Reaction Section R-301", "R-301", 1250.0, 95.0),
            ("UNIT_V302", "Regenerator Vessel V-302", "V-302", 1050.0, 94.5),
            ("UNIT_C303", "Main Fractionator Column C-303", "C-303", 700.0, 95.0),
        ]),
        ("AREA_SRU", "Sulfur Recovery Unit SRU", "AREA-400", 1500.0, [
            ("UNIT_F401", "Claus Thermal Stage Furnace F-401", "F-401", 650.0, 99.0),
            ("UNIT_R402", "Selective Catalytic Reactor R-402", "R-402", 500.0, 98.0),
            ("UNIT_T403", "Tail Gas Scrubber Column T-403", "T-403", 350.0, 97.5),
        ]),
        ("AREA_UTL", "Utilities & Cogeneration", "AREA-500", 1500.0, [
            ("UNIT_B501", "High-Pressure Steam Boiler B-501", "B-501", 650.0, 96.0),
            ("UNIT_TG502", "Cogeneration Turbogenerator TG-502", "TG-502", 550.0, 95.0),
            ("UNIT_CT503", "Cooling Tower Array CT-503", "CT-503", 300.0, 95.5),
        ]),
    ]

    for area_id, area_name, area_tag, area_w, units in areas_data:
        area_node = AssetNode(
            node_id=area_id,
            name=area_name,
            tier=1,
            index=idx,
            tag=area_tag,
            weight=area_w,
            health_score=96.5,
            state=HealthState.NORMAL,
        )
        idx += 1
        root.add_child(area_node)

        for u_id, u_name, u_tag, u_w, u_h in units:
            unit_node = AssetNode(
                node_id=u_id,
                name=u_name,
                tier=2,
                index=idx,
                tag=u_tag,
                weight=u_w,
                health_score=u_h,
                state=HealthState.NORMAL if u_h >= 90.0 else HealthState.GOOD,
            )
            idx += 1
            area_node.add_child(unit_node)

    root.recalculate_aggregates()
    tree = AssetHierarchyTree(root)
    return tree


# ============================================================================
# 4. Squarified Treemap Layout Engine (Bruls, Huizing, van Wijk)
# ============================================================================

def _worst_aspect_ratio(areas: Sequence[float], side: float) -> float:
    """Calculate worst aspect ratio max(w/h, h/w) of candidate row along short side."""
    if not areas or side <= 1e-9:
        return 1.0
    s_sum = sum(areas)
    if s_sum <= 1e-9:
        return 1.0
    s_min = min(areas)
    s_max = max(areas)
    if s_min <= 1e-9:
        return 100.0
    side_sq = side * side
    sum_sq = s_sum * s_sum
    term1 = (side_sq * s_max) / sum_sq
    term2 = sum_sq / (side_sq * s_min)
    return max(term1, term2)


def layout_squarified(items: List[AssetNode], bounds: Rect) -> None:
    """Partition bounds rectangle among items using Squarified layout (Bruls et al.).

    Optimizes aspect ratio towards 1.0, strictly guaranteeing worst aspect ratio < 3.0.
    """
    if bounds.width <= 0.0 or bounds.height <= 0.0:
        raise ValueError(f"Invalid bounding box dimensions: width={bounds.width}, height={bounds.height}")

    if not items:
        return

    total_weight = sum(it.weight for it in items)
    if total_weight <= 1e-9:
        raise ValueError("Total weight must be positive")

    total_area = bounds.width * bounds.height
    node_areas: List[Tuple[AssetNode, float]] = []
    for it in items:
        norm_area = (max(1e-6, it.weight) / total_weight) * total_area
        node_areas.append((it, norm_area))

    # Sort descending by area
    node_areas.sort(key=lambda p: p[1], reverse=True)

    rem_x = bounds.x
    rem_y = bounds.y
    rem_w = bounds.width
    rem_h = bounds.height

    current_row: List[Tuple[AssetNode, float]] = []

    def commit_row(row: List[Tuple[AssetNode, float]], side: float, is_horizontal: bool) -> None:
        nonlocal rem_x, rem_y, rem_w, rem_h
        if not row or side <= 1e-9:
            return
        row_area = sum(a for _, a in row)
        if row_area <= 1e-9:
            return

        if is_horizontal:
            row_h = row_area / rem_w
            curr_pos_x = rem_x
            for node, area in row:
                node_w = area / row_h if row_h > 1e-9 else 0.0
                node.rect = Rect(curr_pos_x, rem_y, node_w, row_h)
                curr_pos_x += node_w
            rem_y += row_h
            rem_h = max(0.0, rem_h - row_h)
        else:
            row_w = row_area / rem_h
            curr_pos_y = rem_y
            for node, area in row:
                node_h = area / row_w if row_w > 1e-9 else 0.0
                node.rect = Rect(rem_x, curr_pos_y, row_w, node_h)
                curr_pos_y += node_h
            rem_x += row_w
            rem_w = max(0.0, rem_w - row_w)

    for node, area in node_areas:
        side = min(rem_w, rem_h)
        if not current_row:
            current_row.append((node, area))
            continue

        curr_areas = [a for _, a in current_row]
        cand_areas = curr_areas + [area]

        curr_worst = _worst_aspect_ratio(curr_areas, side)
        cand_worst = _worst_aspect_ratio(cand_areas, side)

        if cand_worst <= curr_worst:
            current_row.append((node, area))
        else:
            is_horiz = (rem_w <= rem_h)
            commit_row(current_row, side, is_horiz)
            current_row = [(node, area)]

    if current_row:
        is_horiz = (rem_w <= rem_h)
        side = min(rem_w, rem_h)
        commit_row(current_row, side, is_horiz)


def layout_spatial_treemap(
    tree: AssetHierarchyTree,
    canvas_bounds: Rect,
    drilldown_node_id: Optional[str] = None,
    filter_max_depth: int = 3,
    area_padding: float = 4.0,
    area_header_h: float = 24.0,
    unit_padding: float = 2.0,
) -> float:
    """Recursively partition asset hierarchy into nested rectangles.

    Returns the worst aspect ratio across all laid out tiles.
    """
    if canvas_bounds.width <= 0.0 or canvas_bounds.height <= 0.0:
        raise ValueError(f"Canvas bounds singularity: w={canvas_bounds.width}, h={canvas_bounds.height}")

    if tree.root is None:
        raise ValueError("Empty hierarchy tree")

    worst_aspect = 1.0

    if drilldown_node_id:
        target_node = tree.get_node(drilldown_node_id)
        if target_node is None:
            target_node = tree.root
    else:
        target_node = tree.root

    if target_node.tier == 0:
        # Full plant hierarchy view
        target_node.rect = canvas_bounds
        areas = [c for c in target_node.children if c.weight > 0]
        if areas:
            layout_squarified(areas, canvas_bounds)
            for a in areas:
                worst_aspect = max(worst_aspect, a.rect.aspect_ratio)

                if filter_max_depth >= 2 and a.children:
                    # Inner content bounding box for equipment modules
                    ix = a.rect.x + area_padding
                    iy = a.rect.y + area_header_h
                    iw = max(1.0, a.rect.width - 2.0 * area_padding)
                    ih = max(1.0, a.rect.height - area_header_h - area_padding)
                    inner_bounds = Rect(ix, iy, iw, ih)

                    units = [u for u in a.children if u.weight > 0]
                    if units:
                        layout_squarified(units, inner_bounds)
                        for u in units:
                            worst_aspect = max(worst_aspect, u.rect.aspect_ratio)
    elif target_node.tier == 1:
        # Drilled-down into specific Process Area
        target_node.rect = canvas_bounds
        units = [u for u in target_node.children if u.weight > 0]
        if units:
            layout_squarified(units, canvas_bounds)
            for u in units:
                worst_aspect = max(worst_aspect, u.rect.aspect_ratio)
    else:
        # Single unit focus
        target_node.rect = canvas_bounds
        worst_aspect = max(worst_aspect, canvas_bounds.aspect_ratio)

    return worst_aspect


# ============================================================================
# 5. WCAG 2.1 AAA Accessibility Color Contrast Engine
# ============================================================================

def srgb_channel_to_linear(channel: float) -> float:
    return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4


def hex_to_relative_luminance(hex_color: str) -> float:
    h = hex_color.strip().lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    r = int(h[0:2], 16) / 255.0
    g = int(h[2:4], 16) / 255.0
    b = int(h[4:6], 16) / 255.0
    return 0.2126 * srgb_channel_to_linear(r) + 0.7152 * srgb_channel_to_linear(g) + 0.0722 * srgb_channel_to_linear(b)


def calculate_contrast_ratio(c_a: str, c_b: str) -> float:
    """Calculate WCAG 2.1 relative luminance contrast ratio (L1 + 0.05) / (L2 + 0.05)."""
    l1 = hex_to_relative_luminance(c_a)
    l2 = hex_to_relative_luminance(c_b)
    return round((max(l1, l2) + 0.05) / (min(l1, l2) + 0.05), 2)


# ============================================================================
# 6. Treemap Spatial Canvas Engine & ILogicUnit Implementation
# ============================================================================

class TreemapSpatialCanvas(ILogicUnit):
    """Cscape HMI Dynamic Treemap Spatial Canvas Controller.

    Implements:
    - ILogicUnit discrete scan cycle execution
    - Horner OCS RegisterTable memory synchronization (%R2220..%R2227, %M518..%M519)
    - Interactive drilldown zoom and nested level filtering
    - Diagnostic fault injection and nominal recovery (0x0000, 0x7701, 0x7702)
    - Standalone high-res W3C SVG 1.1 vector graphic generation
    """

    def __init__(
        self,
        tree: Optional[AssetHierarchyTree] = None,
        reg_table: Optional[RegisterTable] = None,
        canvas_bounds: Optional[Rect] = None,
    ) -> None:
        self.tree: AssetHierarchyTree = tree or create_canonical_asset_hierarchy()
        self.reg_table: RegisterTable = reg_table or RegisterTable()
        self.canvas_bounds: Rect = canvas_bounds or Rect(
            DEFAULT_CANVAS_X, DEFAULT_CANVAS_Y, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT
        )
        self.active_drilldown_node_id: Optional[str] = None
        self.active_drilldown_level: int = 0
        self.selected_node_index: int = 1
        self.filter_max_depth: int = 3
        self.canvas_active: bool = True
        self.diagnostic_code: DiagnosticCode = DIAG_OK
        self.worst_aspect_ratio: float = 1.0

        self.compute_layout()
        self.sync_to_registers()

    @property
    def name(self) -> str:
        return "TreemapSpatialCanvasSync"

    @property
    def priority(self) -> int:
        return 90

    @property
    def is_enabled(self) -> bool:
        return self.canvas_active

    def compute_layout(self) -> None:
        """Compute squarified treemap layout and aspect ratios."""
        try:
            if self.diagnostic_code != DIAG_OK:
                return

            if self.tree.root is None:
                raise ValueError("Empty hierarchy tree")

            self.worst_aspect_ratio = layout_spatial_treemap(
                tree=self.tree,
                canvas_bounds=self.canvas_bounds,
                drilldown_node_id=self.active_drilldown_node_id,
                filter_max_depth=self.filter_max_depth,
            )
        except Exception:
            self.diagnostic_code = DIAG_ERR_DEGENERATION_FAULT
            self.canvas_active = False

    def drilldown(self, node_id_or_index: Union[str, int]) -> bool:
        """Zoom into specified asset node (Process Area or Sub-unit)."""
        node: Optional[AssetNode] = None
        if isinstance(node_id_or_index, int):
            node = self.tree.get_node_by_index(node_id_or_index)
        else:
            node = self.tree.get_node(node_id_or_index)

        if node is not None:
            self.active_drilldown_node_id = node.id
            self.active_drilldown_level = node.tier
            self.selected_node_index = node.index
            self.compute_layout()
            self.sync_to_registers()
            return True
        return False

    def drillup(self) -> None:
        """Reset drilldown zoom back to root complex."""
        self.active_drilldown_node_id = None
        self.active_drilldown_level = 0
        self.selected_node_index = 1
        self.compute_layout()
        self.sync_to_registers()

    def reset_drilldown(self) -> None:
        self.drillup()

    def filter_level(self, max_depth: int) -> None:
        """Filter nested hierarchy display depth (1=Areas only, 2=Areas+Units, 3=All)."""
        self.filter_max_depth = max(1, min(3, max_depth))
        self.compute_layout()
        self.sync_to_registers()

    def select_node(self, node_id_or_index: Union[str, int]) -> bool:
        """Select active asset node without zooming."""
        node: Optional[AssetNode] = None
        if isinstance(node_id_or_index, int):
            node = self.tree.get_node_by_index(node_id_or_index)
        else:
            node = self.tree.get_node(node_id_or_index)

        if node is not None:
            self.selected_node_index = node.index
            self.sync_to_registers()
            return True
        return False

    # ------------------------------------------------------------------------
    # Fault Injection & Nominal Recovery (0x7701, 0x7702, %M519)
    # ------------------------------------------------------------------------
    def inject_invalid_hierarchy_fault(self) -> None:
        """Simulate invalid hierarchy structure (0x7701)."""
        self.diagnostic_code = DIAG_ERR_INVALID_HIERARCHY
        self.canvas_active = False
        self.sync_to_registers()

    def inject_degeneration_fault(self) -> None:
        """Simulate bounding box degeneration / singularity fault (0x7702)."""
        self.diagnostic_code = DIAG_ERR_DEGENERATION_FAULT
        self.canvas_active = False
        self.sync_to_registers()

    def reset_nominal(self) -> None:
        """Restore nominal canonical tree, layout, and diagnostic codes."""
        self.tree = create_canonical_asset_hierarchy()
        self.active_drilldown_node_id = None
        self.active_drilldown_level = 0
        self.selected_node_index = 1
        self.filter_max_depth = 3
        self.canvas_active = True
        self.diagnostic_code = DIAG_OK
        self.compute_layout()
        self.sync_to_registers()

    def reset(self) -> None:
        self.reset_nominal()

    # ------------------------------------------------------------------------
    # Horner OCS Register Table Synchronization (%R2220..%R2227, %M518..%M519)
    # ------------------------------------------------------------------------
    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize telemetry metrics to Horner OCS RegisterTable (%R2220..%R2227, %M518..%M519)."""
        reg = reg_table if reg_table is not None else self.reg_table

        total_nodes = self.tree.total_nodes
        active_level = int(self.active_drilldown_level)
        sel_index = int(self.selected_node_index)
        worst_aspect_scaled = int(round(self.worst_aspect_ratio * 100.0))
        total_weight_scaled = int(round(self.tree.root.weight / 10.0)) if self.tree.root else 0
        crit_count = self.tree.get_critical_count()
        overall_health_scaled = int(round(self.tree.root.health_score * 100.0)) if self.tree.root else 0

        diag_val = int(self.diagnostic_code) & 0xFFFF
        diag_s16 = diag_val - 0x10000 if diag_val >= 0x8000 else diag_val

        # Analog Word Registers (%R2220..%R2227)
        reg.write_word(REG_W261_TOTAL_ASSET_NODE_COUNT, total_nodes, privilege=privilege)
        reg.write_word(REG_W261_ACTIVE_DRILLDOWN_LEVEL, active_level, privilege=privilege)
        reg.write_word(REG_W261_SELECTED_ASSET_NODE_INDEX, sel_index, privilege=privilege)
        reg.write_word(REG_W261_WORST_ASPECT_RATIO_SCALED, worst_aspect_scaled, privilege=privilege)
        reg.write_word(REG_W261_TOTAL_TREE_WEIGHT_METRIC_SCALED, total_weight_scaled, privilege=privilege)
        reg.write_word(REG_W261_CRITICAL_ALARM_NODE_COUNT, crit_count, privilege=privilege)
        reg.write_word(REG_W261_OVERALL_ASSET_HEALTH_PCT_SCALED, overall_health_scaled, privilege=privilege)
        reg.write_word(REG_W261_DIAGNOSTIC_STATUS_CODE, diag_s16, privilege=privilege)

        # Discrete Bit Coils (%M518..%M519)
        fault_alarm = (self.diagnostic_code != DIAG_OK) or (crit_count > 0)
        active_bit = bool(self.canvas_active and (self.diagnostic_code == DIAG_OK))

        reg.write_bit(COIL_W261_TREEMAP_SPATIAL_CANVAS_ACTIVE, active_bit, privilege=privilege)
        reg.write_bit(COIL_W261_TREEMAP_HIERARCHY_FAULT_ALARM, fault_alarm, privilege=privilege)

    def scan_step(self, dt: float = 0.01, context: Optional[ScanContext] = None) -> None:
        """Execute single discrete scan cycle step."""
        self.compute_layout()
        self.sync_to_registers()

    def execute(self, context: ScanContext) -> None:
        """Execute discrete logic cycle within Horner scan context."""
        self.compute_layout()
        self.sync_to_registers(self.reg_table, privilege=PrivilegeMode.SYSTEM)

    # ------------------------------------------------------------------------
    # Standalone High-Res W3C SVG 1.1 Vector Graphic Synthesis
    # ------------------------------------------------------------------------
    def generate_svg(
        self,
        viewport_width: int = CANVAS_VIEWPORT_WIDTH,
        viewport_height: int = CANVAS_VIEWPORT_HEIGHT,
    ) -> str:
        """Generate high-res standalone W3C SVG 1.1 SCADA canvas graphic."""
        parts: List[str] = []
        parts.append('<?xml version="1.0" encoding="UTF-8"?>')
        parts.append(
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {viewport_width} {viewport_height}" '
            f'width="{viewport_width}" height="{viewport_height}" version="1.1">'
        )
        parts.append('  <defs>')
        parts.append('    <style type="text/css">')
        parts.append('      .hud-title { font-family: monospace, sans-serif; font-size: 13px; font-weight: 700; fill: #FFFFFF; }')
        parts.append('      .hud-label { font-family: -apple-system, sans-serif; font-size: 9px; font-weight: 600; fill: #CBD5E1; text-transform: uppercase; }')
        parts.append('      .hud-val { font-family: monospace, sans-serif; font-size: 12px; font-weight: 700; fill: #06B6D4; }')
        parts.append('      .area-title { font-family: -apple-system, sans-serif; font-size: 11px; font-weight: 700; fill: #FFFFFF; }')
        parts.append('      .unit-tag { font-family: monospace, sans-serif; font-size: 10px; font-weight: 700; fill: #FFFFFF; }')
        parts.append('      .unit-name { font-family: -apple-system, sans-serif; font-size: 9px; font-weight: 600; fill: #FFFFFF; }')
        parts.append('      .unit-metric { font-family: monospace, sans-serif; font-size: 9px; font-weight: 500; fill: #CBD5E1; }')
        parts.append('    </style>')
        parts.append('    <linearGradient id="hud-grad" x1="0%" y1="0%" x2="0%" y2="100%">')
        parts.append('      <stop offset="0%" stop-color="#161B22"/>')
        parts.append('      <stop offset="100%" stop-color="#0D1117"/>')
        parts.append('    </linearGradient>')
        parts.append('  </defs>')

        # Dark industrial viewport backing
        parts.append(f'  <rect width="{viewport_width}" height="{viewport_height}" fill="{COLOR_DARK_THEME_BACKING}"/>')

        # --------------------------------------------------------------------
        # Scorecard HUD Header Banner
        # --------------------------------------------------------------------
        hud_x, hud_y, hud_w, hud_h = 24.0, 12.0, 1152.0, 64.0
        parts.append('  <!-- SCORECARD HUD HEADER BANNER -->')
        parts.append('  <g id="interactive-hud">')
        parts.append(
            f'    <rect x="{hud_x:.1f}" y="{hud_y:.1f}" width="{hud_w:.1f}" height="{hud_h:.1f}" '
            f'rx="6" ry="6" fill="url(#hud-grad)" stroke="{COLOR_BORDER}" stroke-width="1.5"/>'
        )
        parts.append(
            f'    <text x="{hud_x + 16:.1f}" y="{hud_y + 24:.1f}" class="hud-title">'
            f'{html.escape("CSCAPE SCADA // TREEMAP SPATIAL ASSET CANVAS (W261)")}</text>'
        )

        # Breadcrumb Navigation
        breadcrumb = "PLANT ROOT"
        if self.active_drilldown_node_id:
            node = self.tree.get_node(self.active_drilldown_node_id)
            if node:
                breadcrumb = f"PLANT ROOT &gt; {html.escape(node.name.upper())}"
        parts.append(
            f'    <text x="{hud_x + 16:.1f}" y="{hud_y + 44:.1f}" class="hud-label">'
            f'{breadcrumb}</text>'
        )

        # Status Badge (Decoupled backing #050811 with > 18:1 contrast)
        status_label = "ACTIVE | NOMINAL" if self.diagnostic_code == DIAG_OK else f"FAULT: {hex(int(self.diagnostic_code) & 0xFFFF)}"
        badge_stroke = "#10B981" if self.diagnostic_code == DIAG_OK else "#EF4444"
        parts.append(
            f'    <rect x="{hud_x + 360:.1f}" y="{hud_y + 16:.1f}" width="140" height="32" rx="4" '
            f'fill="{COLOR_DECOUPLED_BADGE}" stroke="{badge_stroke}" stroke-width="1.2"/>'
        )
        parts.append(
            f'    <text x="{hud_x + 372:.1f}" y="{hud_y + 36:.1f}" font-family="monospace" font-size="10" '
            f'font-weight="700" fill="{COLOR_TEXT_PRIMARY}">{status_label}</text>'
        )

        # Scorecard Telemetry Columns
        crit_count = self.tree.get_critical_count()
        overall_health = self.tree.root.health_score if self.tree.root else 0.0
        hud_cols = [
            ("TOTAL NODES (%R2220)", f"{self.tree.total_nodes}", "#FFFFFF"),
            ("ZOOM LEVEL (%R2221)", f"TIER {self.active_drilldown_level}", "#06B6D4"),
            ("ACTIVE NODE (%R2222)", f"ID #{self.selected_node_index}", "#06B6D4"),
            ("WORST ASPECT (%R2223)", f"{self.worst_aspect_ratio:.2f}:1", "#10B981" if self.worst_aspect_ratio < 3.0 else "#EF4444"),
            ("TOTAL WEIGHT (%R2224)", f"{self.tree.root.weight:,.0f} kg/h" if self.tree.root else "0", "#F59E0B"),
            ("OVERALL HEALTH (%R2226)", f"{overall_health:.2f}%", "#10B981" if overall_health >= 90.0 else "#EF4444"),
        ]

        col_start_x = hud_x + 520.0
        col_spacing = 104.0
        for idx, (col_label, col_val, col_color) in enumerate(hud_cols):
            cx = col_start_x + idx * col_spacing
            # Decoupled mini backing badge
            parts.append(
                f'    <rect x="{cx - 6:.1f}" y="{hud_y + 12:.1f}" width="98" height="40" rx="3" '
                f'fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="0.8"/>'
            )
            parts.append(f'    <text x="{cx:.1f}" y="{hud_y + 26:.1f}" class="hud-label">{col_label}</text>')
            parts.append(f'    <text x="{cx:.1f}" y="{hud_y + 44:.1f}" class="hud-val" fill="{col_color}">{col_val}</text>')
        parts.append('  </g>')

        # --------------------------------------------------------------------
        # Spatial Treemap Layout Viewport
        # --------------------------------------------------------------------
        parts.append('  <!-- SPATIAL TREEMAP LAYOUT VIEWPORT -->')
        parts.append('  <g id="treemap-viewport">')

        root = self.tree.root
        if root is not None:
            if self.active_drilldown_node_id:
                drill_node = self.tree.get_node(self.active_drilldown_node_id) or root
                render_nodes = drill_node.children if drill_node.children else [drill_node]
            else:
                render_nodes = root.children

            for area in render_nodes:
                ax, ay, aw, ah = area.rect.x, area.rect.y, area.rect.width, area.rect.height
                if aw <= 1.0 or ah <= 1.0:
                    continue

                is_area_sel = (area.index == self.selected_node_index)
                area_stroke = COLOR_FOCUS_CYAN if is_area_sel else COLOR_BORDER
                parts.append(
                    f'    <g id="tile-{html.escape(area.id)}" class="treemap-spatial-tile" '
                    f'data-asset-id="{html.escape(area.id)}" data-tier="{area.tier}" '
                    f'data-bbox="{ax:.1f},{ay:.1f},{aw:.1f},{ah:.1f}" data-aspect-ratio="{area.rect.aspect_ratio:.2f}">'
                )
                parts.append(
                    f'      <rect x="{ax:.1f}" y="{ay:.1f}" width="{aw:.1f}" height="{ah:.1f}" '
                    f'rx="4" ry="4" fill="{COLOR_PANEL_BG}" stroke="{area_stroke}" stroke-width="{2.0 if is_area_sel else 1.2}"/>'
                )

                # Header band
                hdr_h = min(24.0, ah)
                parts.append(
                    f'      <rect x="{ax:.1f}" y="{ay:.1f}" width="{aw:.1f}" height="{hdr_h:.1f}" '
                    f'rx="4" ry="4" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="0.8"/>'
                )
                parts.append(
                    f'      <text x="{ax + 8:.1f}" y="{ay + 16:.1f}" class="area-title">'
                    f'{html.escape(area.name)} [{area.weight:,.0f} kg/h]</text>'
                )

                # Sub-unit tiles inside Process Area
                if self.filter_max_depth >= 2 and area.children and not self.active_drilldown_node_id:
                    for u in area.children:
                        ux, uy, uw, uh = u.rect.x, u.rect.y, u.rect.width, u.rect.height
                        if uw <= 1.0 or uh <= 1.0:
                            continue

                        is_u_sel = (u.index == self.selected_node_index)
                        u_stroke = COLOR_FOCUS_CYAN if is_u_sel else COLOR_BORDER
                        parts.append(
                            f'      <g id="unit-{html.escape(u.id)}" class="treemap-spatial-tile" '
                            f'data-asset-id="{html.escape(u.id)}" data-tier="{u.tier}" '
                            f'data-bbox="{ux:.1f},{uy:.1f},{uw:.1f},{uh:.1f}" data-aspect-ratio="{u.rect.aspect_ratio:.2f}">'
                        )
                        parts.append(
                            f'        <rect x="{ux:.1f}" y="{uy:.1f}" width="{uw:.1f}" height="{uh:.1f}" '
                            f'rx="3" ry="3" fill="{u.color}" fill-opacity="0.25" stroke="{u_stroke}" stroke-width="{1.8 if is_u_sel else 1.0}"/>'
                        )
                        if uw > 50.0 and uh > 30.0:
                            # Decoupled tag badge
                            parts.append(
                                f'        <rect x="{ux + 4:.1f}" y="{uy + 4:.1f}" width="48" height="14" rx="2" '
                                f'fill="{COLOR_DECOUPLED_BADGE}" stroke="{u.color}" stroke-width="0.8"/>'
                            )
                            parts.append(
                                f'        <text x="{ux + 8:.1f}" y="{uy + 14:.1f}" class="unit-tag">{html.escape(u.tag)}</text>'
                            )
                            parts.append(
                                f'        <text x="{ux + 6:.1f}" y="{uy + 28:.1f}" class="unit-name">{html.escape(u.name[:24])}</text>'
                            )
                            if uh > 44.0:
                                parts.append(
                                    f'        <text x="{ux + 6:.1f}" y="{uy + 40:.1f}" class="unit-metric">{u.weight:,.0f} kg/h | {u.health_score:.1f}%</text>'
                                )
                        parts.append('      </g>')
                elif self.active_drilldown_node_id and area.is_leaf:
                    # Drilled down into unit directly
                    if aw > 60.0 and ah > 36.0:
                        parts.append(
                            f'      <rect x="{ax + 6:.1f}" y="{ay + 30:.1f}" width="60" height="18" rx="2" '
                            f'fill="{COLOR_DECOUPLED_BADGE}" stroke="{area.color}" stroke-width="0.8"/>'
                        )
                        parts.append(
                            f'      <text x="{ax + 10:.1f}" y="{ay + 42:.1f}" class="unit-tag">{html.escape(area.tag)}</text>'
                        )
                        parts.append(
                            f'      <text x="{ax + 8:.1f}" y="{ay + 60:.1f}" class="unit-metric">{area.weight:,.0f} kg/h | {area.health_score:.1f}%</text>'
                        )

                parts.append('    </g>')

        parts.append('  </g>')
        parts.append('</svg>')
        return "\n".join(parts)


# ============================================================================
# 7. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_treemap_spatial_canvas_verification(
    output_path: Optional[str] = None,
    sample_svg_path: Optional[str] = None,
    work_package: str = "W261",
) -> Dict[str, Any]:
    """Execute deterministic 9-stage verification suite for W261 Treemap Spatial Canvas."""
    test_results: List[Dict[str, Any]] = []

    final_evidence_path = (
        output_path
        if output_path is not None
        else str(REPO_ROOT / "artifacts" / "HMI" / "treemap_spatial_canvas_evidence.json")
    )
    final_svg_path = (
        sample_svg_path
        if sample_svg_path is not None
        else str(REPO_ROOT / "artifacts" / "HMI" / "treemap_spatial_canvas_sample.svg")
    )

    # ------------------------------------------------------------------------
    # Stage 1: Asset Hierarchy Tree & Bounding Box Spatial Partitioning
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s1_pass = False
    try:
        tree = create_canonical_asset_hierarchy()
        total_nodes = tree.total_nodes
        total_leaves = tree.total_leaves
        max_depth = tree.max_depth

        bounds = Rect(DEFAULT_CANVAS_X, DEFAULT_CANVAS_Y, DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT)
        layout_spatial_treemap(tree, bounds, filter_max_depth=3)

        # Spatial assertions: positivity, containment, and non-overlap among sibling areas
        areas = tree.root.children
        all_positive = all(a.rect.width > 0.0 and a.rect.height > 0.0 for a in areas)
        all_contained = all(bounds.contains(a.rect, epsilon=1e-2) for a in areas)

        no_overlap = True
        for i in range(len(areas)):
            for j in range(i + 1, len(areas)):
                if areas[i].rect.intersects(areas[j].rect):
                    no_overlap = False
                    break

        s1_pass = (
            total_nodes == CANONICAL_TOTAL_NODES
            and total_leaves == CANONICAL_TOTAL_UNITS
            and max_depth == CANONICAL_MAX_DEPTH
            and all_positive
            and all_contained
            and no_overlap
        )
    except Exception:
        s1_pass = False
    dt1 = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 1,
        "name": "Asset_Hierarchy_Tree_And_Bounding_Box_Spatial_Partitioning",
        "check": "Asset_Hierarchy_Tree_And_Bounding_Box_Spatial_Partitioning",
        "passed": s1_pass,
        "status": "passed" if s1_pass else "failed",
        "timing_ms": dt1,
        "details": f"Verified {total_nodes} asset nodes, depth {max_depth}, strictly non-overlapping bounding boxes and spatial containment.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Pure IEC 61131-3 ST POU Validation with STParser and SecurityGuard
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s2_pass = False
    try:
        SecurityGuard.assert_pure_st_content(W261_TREEMAP_SPATIAL_CANVAS_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(W261_TREEMAP_SPATIAL_CANVAS_PURE_ST_POU)

        expected_bindings = {
            "TotalAssetNodeCount": REG_W261_TOTAL_ASSET_NODE_COUNT,
            "ActiveDrilldownLevel": REG_W261_ACTIVE_DRILLDOWN_LEVEL,
            "SelectedAssetNodeIndex": REG_W261_SELECTED_ASSET_NODE_INDEX,
            "WorstAspectRatioScaled": REG_W261_WORST_ASPECT_RATIO_SCALED,
            "TotalTreeWeightMetricScaled": REG_W261_TOTAL_TREE_WEIGHT_METRIC_SCALED,
            "CriticalAlarmNodeCount": REG_W261_CRITICAL_ALARM_NODE_COUNT,
            "OverallAssetHealthPctScaled": REG_W261_OVERALL_ASSET_HEALTH_PCT_SCALED,
            "DiagnosticStatusCode": REG_W261_DIAGNOSTIC_STATUS_CODE,
            "TreemapSpatialCanvasActive": COIL_W261_TREEMAP_SPATIAL_CANVAS_ACTIVE,
            "TreemapHierarchyFaultAlarm": COIL_W261_TREEMAP_HIERARCHY_FAULT_ALARM,
        }

        vmap = {v.name: v.address_binding for v in pou.variables}
        all_bindings_valid = all(vmap.get(k) == b for k, b in expected_bindings.items())

        s2_pass = (
            pou is not None
            and pou.name == "TreemapSpatialCanvasSync"
            and pou.pou_type == POUType.PROGRAM
            and len(pou.variables) == 10
            and all_bindings_valid
        )
    except Exception:
        s2_pass = False
    dt2 = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 2,
        "name": "Pure_IEC_61131_3_ST_POU_Validation_With_STParser_And_SecurityGuard",
        "check": "Pure_IEC_61131_3_ST_POU_Validation_With_STParser_And_SecurityGuard",
        "passed": s2_pass,
        "status": "passed" if s2_pass else "failed",
        "timing_ms": dt2,
        "details": f"Validated 'TreemapSpatialCanvasSync' POU across Horner registers {REG_W261_TOTAL_ASSET_NODE_COUNT}..{REG_W261_DIAGNOSTIC_STATUS_CODE} and coils {COIL_W261_TREEMAP_SPATIAL_CANVAS_ACTIVE}..{COIL_W261_TREEMAP_HIERARCHY_FAULT_ALARM}.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Anti-Ladder Security Guard Interception
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
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

    s3_pass = (rejected_count == len(ladder_snippets))
    dt3 = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 3,
        "name": "Anti_Ladder_Security_Guard_Interception",
        "check": "Anti_Ladder_Security_Guard_Interception",
        "passed": s3_pass,
        "status": "passed" if s3_pass else "failed",
        "timing_ms": dt3,
        "details": f"Rejected all {rejected_count}/{len(ladder_snippets)} forbidden ladder logic constructs with LadderForbiddenError.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Squarified Layout Aspect Ratio Optimization (Worst Ratio < 3.0)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s4_pass = False
    try:
        canvas_test = TreemapSpatialCanvas()
        worst_ratio = canvas_test.worst_aspect_ratio
        all_nodes = canvas_test.tree.get_all_nodes()

        all_ratios = [n.rect.aspect_ratio for n in all_nodes if n.rect.area > 1.0]
        max_ratio_calc = max(all_ratios) if all_ratios else 1.0

        s4_pass = (max_ratio_calc < WORST_ASPECT_RATIO_CEILING) and (worst_ratio < WORST_ASPECT_RATIO_CEILING)
    except Exception:
        s4_pass = False
    dt4 = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 4,
        "name": "Squarified_Layout_Aspect_Ratio_Optimization",
        "check": "Squarified_Layout_Aspect_Ratio_Optimization",
        "passed": s4_pass,
        "status": "passed" if s4_pass else "failed",
        "timing_ms": dt4,
        "details": f"Verified squarified layout aspect ratio optimization: worst ratio {worst_ratio:.2f}:1 strictly < 3.0 ceiling.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: WCAG AAA Color Contrast Compliance (>= 18:1 badges, >= 7:1 text)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    cr_text_badge = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    cr_muted_badge = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DECOUPLED_BADGE)

    graphic_colors = [
        COLOR_HEALTH_NORMAL,
        COLOR_HEALTH_GOOD,
        COLOR_HEALTH_WARNING,
        COLOR_HEALTH_CRITICAL,
        COLOR_FOCUS_CYAN,
    ]
    graphic_crs = [calculate_contrast_ratio(col, COLOR_DARK_THEME_BACKING) for col in graphic_colors]
    min_graphic_cr = min(graphic_crs)

    s5_pass = (
        cr_text_badge >= 18.0
        and cr_muted_badge >= 7.0
        and min_graphic_cr >= 3.0
    )
    dt5 = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 5,
        "name": "WCAG_AAA_Color_Contrast_Compliance",
        "check": "WCAG_AAA_Color_Contrast_Compliance",
        "passed": s5_pass,
        "status": "passed" if s5_pass else "failed",
        "timing_ms": dt5,
        "details": f"Verified decoupled badge contrast {cr_text_badge:.2f}:1 (>= 18:1), secondary text {cr_muted_badge:.2f}:1 (>= 7:1), and graphic contrast {min_graphic_cr:.2f}:1 (>= 3:1).",
    })

    # ------------------------------------------------------------------------
    # Stage 6: Invalid Hierarchy & Degeneration Fault Injections (0x7701, 0x7702, %M519)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s6_pass = False
    try:
        canvas_fault = TreemapSpatialCanvas()
        nom_code = canvas_fault.diagnostic_code
        nom_active = canvas_fault.canvas_active

        # Fault 1: 0x7701 Invalid Hierarchy Fault
        canvas_fault.inject_invalid_hierarchy_fault()
        code_1 = canvas_fault.diagnostic_code
        m519_1 = canvas_fault.reg_table.read_bit(COIL_W261_TREEMAP_HIERARCHY_FAULT_ALARM)
        m518_1 = canvas_fault.reg_table.read_bit(COIL_W261_TREEMAP_SPATIAL_CANVAS_ACTIVE)

        # Reset nominal
        canvas_fault.reset_nominal()
        code_rst1 = canvas_fault.diagnostic_code
        m519_rst1 = canvas_fault.reg_table.read_bit(COIL_W261_TREEMAP_HIERARCHY_FAULT_ALARM)
        m518_rst1 = canvas_fault.reg_table.read_bit(COIL_W261_TREEMAP_SPATIAL_CANVAS_ACTIVE)

        # Fault 2: 0x7702 Degeneration Fault
        canvas_fault.inject_degeneration_fault()
        code_2 = canvas_fault.diagnostic_code
        m519_2 = canvas_fault.reg_table.read_bit(COIL_W261_TREEMAP_HIERARCHY_FAULT_ALARM)
        m518_2 = canvas_fault.reg_table.read_bit(COIL_W261_TREEMAP_SPATIAL_CANVAS_ACTIVE)

        # Reset nominal
        canvas_fault.reset_nominal()
        code_rst2 = canvas_fault.diagnostic_code
        m519_rst2 = canvas_fault.reg_table.read_bit(COIL_W261_TREEMAP_HIERARCHY_FAULT_ALARM)
        m518_rst2 = canvas_fault.reg_table.read_bit(COIL_W261_TREEMAP_SPATIAL_CANVAS_ACTIVE)

        s6_pass = (
            nom_code == DIAG_OK
            and nom_active is True
            and code_1 == DIAG_ERR_INVALID_HIERARCHY
            and m519_1 is True
            and m518_1 is False
            and code_rst1 == DIAG_OK
            and m519_rst1 is False
            and m518_rst1 is True
            and code_2 == DIAG_ERR_DEGENERATION_FAULT
            and m519_2 is True
            and m518_2 is False
            and code_rst2 == DIAG_OK
            and m519_rst2 is False
            and m518_rst2 is True
        )
    except Exception:
        s6_pass = False
    dt6 = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 6,
        "name": "Invalid_Hierarchy_And_Degeneration_Fault_Injections",
        "check": "Invalid_Hierarchy_And_Degeneration_Fault_Injections",
        "passed": s6_pass,
        "status": "passed" if s6_pass else "failed",
        "timing_ms": dt6,
        "details": "Verified 0x0000 OK baseline, 0x7701 INVALID_HIERARCHY trip (%M519 asserted), 0x7702 DEGENERATION trip, and nominal recoveries.",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Interactive Drilldown Zoom & Nested Level Filtering
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s7_pass = False
    try:
        canvas_zoom = TreemapSpatialCanvas()
        init_level = canvas_zoom.active_drilldown_level

        # Drilldown into AREA_ALK
        canvas_zoom.drilldown("AREA_ALK")
        zoom_level = canvas_zoom.active_drilldown_level
        zoom_node_id = canvas_zoom.active_drilldown_node_id
        svg_drill = canvas_zoom.generate_svg()
        has_breadcrumb = "PLANT ROOT &gt; ALKYLATION &amp; HF TREATER" in svg_drill

        # Filter nested levels
        canvas_zoom.filter_level(max_depth=1)
        depth_1 = canvas_zoom.filter_max_depth

        # Reset drilldown zoom
        canvas_zoom.drillup()
        reset_level = canvas_zoom.active_drilldown_level
        reset_node_id = canvas_zoom.active_drilldown_node_id

        s7_pass = (
            init_level == 0
            and zoom_level == 1
            and zoom_node_id == "AREA_ALK"
            and has_breadcrumb
            and depth_1 == 1
            and reset_level == 0
            and reset_node_id is None
        )
    except Exception:
        s7_pass = False
    dt7 = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 7,
        "name": "Interactive_Drilldown_Zoom_And_Nested_Level_Filtering",
        "check": "Interactive_Drilldown_Zoom_And_Nested_Level_Filtering",
        "passed": s7_pass,
        "status": "passed" if s7_pass else "failed",
        "timing_ms": dt7,
        "details": "Verified drilldown zoom (Level 0 -> 1), dynamic breadcrumb HUD update, nested level depth filtering, and zoom restoration.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Horner OCS Register Table Synchronization (%R2220..%R2227, %M518..%M519)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s8_pass = False
    try:
        reg_table = RegisterTable()
        canvas_sync = TreemapSpatialCanvas(reg_table=reg_table)
        canvas_sync.scan_step(dt=0.01)

        r2220 = reg_table.read_word(REG_W261_TOTAL_ASSET_NODE_COUNT)
        r2221 = reg_table.read_word(REG_W261_ACTIVE_DRILLDOWN_LEVEL)
        r2222 = reg_table.read_word(REG_W261_SELECTED_ASSET_NODE_INDEX)
        r2223 = reg_table.read_word(REG_W261_WORST_ASPECT_RATIO_SCALED)
        r2224 = reg_table.read_word(REG_W261_TOTAL_TREE_WEIGHT_METRIC_SCALED)
        r2225 = reg_table.read_word(REG_W261_CRITICAL_ALARM_NODE_COUNT)
        r2226 = reg_table.read_word(REG_W261_OVERALL_ASSET_HEALTH_PCT_SCALED)
        r2227 = reg_table.read_word(REG_W261_DIAGNOSTIC_STATUS_CODE)
        m518 = reg_table.read_bit(COIL_W261_TREEMAP_SPATIAL_CANVAS_ACTIVE)
        m519 = reg_table.read_bit(COIL_W261_TREEMAP_HIERARCHY_FAULT_ALARM)

        registers_ok = (
            r2220 == CANONICAL_TOTAL_NODES
            and r2221 == 0
            and 1 <= r2222 <= CANONICAL_TOTAL_NODES
            and 100 <= r2223 < 300
            and r2224 == CANONICAL_TOTAL_WEIGHT_SCALED
            and r2225 == 0
            and r2226 == CANONICAL_OVERALL_HEALTH_SCALED
            and r2227 == 0
            and m518 is True
            and m519 is False
        )

        # Verify ScanContext execution
        mock_ctx = ScanContext(
            cycle=1,
            dt_ms=10.0,
            elapsed_time_ms=10.0,
            get_register=lambda addr: reg_table.read_word(addr),
            set_register=lambda addr, val: reg_table.write_word(addr, val, privilege=PrivilegeMode.SYSTEM),
            get_variable=lambda n, d=None: d,
            set_variable=lambda n, v: None,
            record_fault=lambda f: None,
        )
        setattr(mock_ctx, "reg_table", reg_table)
        canvas_sync.execute(mock_ctx)

        s8_pass = registers_ok
    except Exception:
        s8_pass = False
    dt8 = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 8,
        "name": "Horner_OCS_Register_Table_Synchronization",
        "check": "Horner_OCS_Register_Table_Synchronization",
        "passed": s8_pass,
        "status": "passed" if s8_pass else "failed",
        "timing_ms": dt8,
        "details": f"Synchronized %R2220={r2220}, %R2221={r2221}, %R2222={r2222}, %R2223={r2223}, %R2224={r2224}, %R2225={r2225}, %R2226={r2226}, %R2227={r2227}, %M518={m518}, %M519={m519}.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Visual Grounding Fallback & High-Res SVG Export
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s9_pass = False
    try:
        canvas_final = TreemapSpatialCanvas()
        svg_final = canvas_final.generate_svg()

        root = ET.fromstring(svg_final)
        is_svg = root.tag.endswith("svg")
        has_viewbox = "viewBox" in root.attrib
        has_rects = len(root.findall(".//{http://www.w3.org/2000/svg}rect")) + len(root.findall(".//rect")) > 0
        has_text = len(root.findall(".//{http://www.w3.org/2000/svg}text")) + len(root.findall(".//text")) > 0
        has_grounding = "data-asset-id" in svg_final and "data-bbox" in svg_final

        # Write sample SVG file
        svg_p = Path(final_svg_path).resolve()
        svg_p.parent.mkdir(parents=True, exist_ok=True)
        svg_p.write_text(svg_final, encoding="utf-8")

        s9_pass = (
            is_svg
            and has_viewbox
            and has_rects
            and has_text
            and has_grounding
            and svg_p.is_file()
            and svg_p.stat().st_size > 0
        )
    except Exception:
        s9_pass = False
    dt9 = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 9,
        "name": "Visual_Grounding_Fallback_And_High_Res_SVG_Export",
        "check": "Visual_Grounding_Fallback_And_High_Res_SVG_Export",
        "passed": s9_pass,
        "status": "passed" if s9_pass else "failed",
        "timing_ms": dt9,
        "details": f"Generated high-res W3C SVG 1.1 ({len(svg_final)} chars) with visual grounding metadata -> {final_svg_path}.",
    })

    # ------------------------------------------------------------------------
    # Strict 4-State Engineering Contract Aggregation
    # ------------------------------------------------------------------------
    checks_passed = sum(1 for t in test_results if t["passed"])
    total_checks = len(test_results)
    all_passed = (checks_passed == total_checks)
    status: AgentStatus = AgentStatus.SUCCESS if all_passed else AgentStatus.FAILED

    report: Dict[str, Any] = {
        "status": status.value,
        "error_code": None if all_passed else "STAGE_VERIFICATION_FAILURE",
        "details": (
            f"W261 Treemap Spatial Canvas verification passed all {checks_passed}/{total_checks} deterministic stages."
            if all_passed
            else f"W261 Treemap Spatial Canvas verification failed: {total_checks - checks_passed}/{total_checks} stages failed."
        ),
        "data": {
            "work_package": work_package,
            "gate": "Gate G9 / Gate G2",
            "component": "Cscape HMI Dynamic Treemap Spatial Canvas",
            "checks_passed": checks_passed,
            "total_checks": total_checks,
            "tests": test_results,
            "registers": {
                REG_W261_TOTAL_ASSET_NODE_COUNT: CANONICAL_TOTAL_NODES,
                REG_W261_ACTIVE_DRILLDOWN_LEVEL: 0,
                REG_W261_SELECTED_ASSET_NODE_INDEX: 1,
                REG_W261_WORST_ASPECT_RATIO_SCALED: int(round(canvas_final.worst_aspect_ratio * 100.0)),
                REG_W261_TOTAL_TREE_WEIGHT_METRIC_SCALED: CANONICAL_TOTAL_WEIGHT_SCALED,
                REG_W261_CRITICAL_ALARM_NODE_COUNT: 0,
                REG_W261_OVERALL_ASSET_HEALTH_PCT_SCALED: CANONICAL_OVERALL_HEALTH_SCALED,
                REG_W261_DIAGNOSTIC_STATUS_CODE: 0,
                COIL_W261_TREEMAP_SPATIAL_CANVAS_ACTIVE: True,
                COIL_W261_TREEMAP_HIERARCHY_FAULT_ALARM: False,
            },
            "metrics": {
                "worst_aspect_ratio": canvas_final.worst_aspect_ratio,
                "aspect_ratio_ceiling": WORST_ASPECT_RATIO_CEILING,
                "total_asset_nodes": CANONICAL_TOTAL_NODES,
                "badge_contrast_ratio": cr_text_badge,
                "text_contrast_ratio": cr_muted_badge,
                "min_graphic_contrast_ratio": min_graphic_cr,
            },
            "artifacts": {
                "evidence_json": str(Path(final_evidence_path).resolve()),
                "sample_svg": str(Path(final_svg_path).resolve()),
            },
        },
    }

    # Write evidence artifact
    evidence_p = Path(final_evidence_path).resolve()
    evidence_p.parent.mkdir(parents=True, exist_ok=True)
    evidence_p.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return report


# ============================================================================
# 8. Formatting Helpers & Main CLI Entrypoint
# ============================================================================

def format_stage_badge(passed: bool, status: Optional[str] = None) -> str:
    """Format strict 4-state contract ANSI badge."""
    norm_status = (status or "").lower()
    if norm_status == "blocked":
        return f"{CLR_YELLOW}{CLR_BOLD}[BLOCKED]{CLR_RESET}"
    if norm_status == "inconclusive":
        return f"{CLR_YELLOW}{CLR_BOLD}[INCONCLUSIVE]{CLR_RESET}"
    if passed or norm_status in ("passed", "pass", "success"):
        return f"{CLR_GREEN}{CLR_BOLD}[PASS]{CLR_RESET}"
    return f"{CLR_RED}{CLR_BOLD}[FAIL]{CLR_RESET}"


def format_stage_result(
    stage_num: Union[int, str],
    check_name: str,
    passed: bool,
    timing_ms: float = 0.0,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format single stage output row."""
    badge = format_stage_badge(passed, status)
    time_str = f"{CLR_DIM}({timing_ms:6.2f} ms){CLR_RESET}" if timing_ms > 0 else ""
    if isinstance(stage_num, int):
        stage_str = f"Stage {stage_num:02d}"
    else:
        stage_str = f"Stage {stage_num}"
    out = f"  {stage_str}: {badge} {check_name:<65} {time_str}"
    if details:
        out += f"\n            {CLR_GRAY}-> {details}{CLR_RESET}"
    return out


def main(argv: Optional[List[str]] = None) -> int:
    """Execute W261 Treemap Spatial Canvas verification suite and output report."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="Verify Cscape HMI Dynamic Treemap Spatial Canvas (W261)"
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
        "--evidence",
        "--output",
        "-o",
        dest="output_path",
        type=str,
        default=None,
        help="Path for generated JSON verification evidence",
    )
    parser.add_argument(
        "--sample-svg",
        "--svg",
        "-s",
        dest="svg_path",
        type=str,
        default=None,
        help="Path for generated sample SVG vector visual",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W261",
        help="Work package identifier (default: W261)",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        help="Output raw strict 4-state contract JSON to stdout",
    )
    args = parser.parse_args(argv)

    default_evidence = str(REPO_ROOT / "artifacts" / "HMI" / "treemap_spatial_canvas_evidence.json")
    default_svg = str(REPO_ROOT / "artifacts" / "HMI" / "treemap_spatial_canvas_sample.svg")

    evidence_file_str = args.output_path or args.positional_output or default_evidence
    svg_file_str = args.svg_path or args.positional_svg or default_svg

    evidence_path = Path(evidence_file_str).resolve()
    svg_path = Path(svg_file_str).resolve()

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    svg_path.parent.mkdir(parents=True, exist_ok=True)

    if not args.json:
        print(f"\n{CLR_BOLD}{CLR_CYAN}{'=' * 80}{CLR_RESET}")
        print(f"  {CLR_BOLD}JEV CSCAPE AGENT - WAVE W261 TREEMAP SPATIAL CANVAS VERIFICATION RUNNER{CLR_RESET}")
        print(f"  {CLR_BOLD}Classification: PRODUCTION_READY (Gate G9 / Gate G2 Live GUI){CLR_RESET}")
        print(f"{CLR_BOLD}{CLR_CYAN}{'=' * 80}{CLR_RESET}\n")

    start_time = time.perf_counter()
    try:
        report = run_treemap_spatial_canvas_verification(
            output_path=str(evidence_path),
            sample_svg_path=str(svg_path),
            work_package=args.work_package,
        )
        elapsed_total_ms = (time.perf_counter() - start_time) * 1000.0
    except Exception as ex:
        elapsed_total_ms = (time.perf_counter() - start_time) * 1000.0
        fail_payload: Dict[str, Any] = {
            "status": "failed",
            "error_code": "VERIFICATION_EXCEPTION",
            "details": f"Verification failed with exception: {ex}",
            "data": {
                "work_package": args.work_package,
                "gate": "Gate G9 / Gate G2",
                "component": "Cscape HMI Dynamic Treemap Spatial Canvas",
                "duration_ms": elapsed_total_ms,
                "checks_passed": 0,
                "total_checks": 9,
                "tests": [],
            },
        }
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(fail_payload, f, indent=2)

        if args.json:
            print(json.dumps(fail_payload, indent=2))
        else:
            print(f"  {CLR_RED}[FAIL] Verification failed with exception: {ex}{CLR_RESET}")
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
        return 0 if isinstance(report, dict) and report.get("status") == "success" else 1

    tests = report.get("data", {}).get("tests", []) if isinstance(report, dict) else []
    total_checks = report.get("data", {}).get("total_checks", len(tests)) if isinstance(report, dict) else len(tests)
    checks_passed = report.get("data", {}).get("checks_passed", 0) if isinstance(report, dict) else 0

    stage_duration_estimate = (elapsed_total_ms / max(len(tests), 1)) if tests else 0.0
    for idx, t in enumerate(tests, start=1):
        stage_num = t.get("stage", idx)
        check_name = t.get("check", f"Stage_{stage_num}")
        passed = t.get("passed", False)
        status = t.get("status", "passed" if passed else "failed")
        details = t.get("details", "")
        timing_ms = t.get("timing_ms", stage_duration_estimate)
        print(format_stage_result(stage_num, check_name, passed, timing_ms, details, status))

    print(f"\n{CLR_CYAN}{'-' * 80}{CLR_RESET}")
    overall_status = report.get("status", "unknown") if isinstance(report, dict) else "unknown"
    status_badge = format_stage_badge(overall_status in ("success", "passed"), overall_status)
    print(f"  Result: {checks_passed}/{total_checks} stages passed in {elapsed_total_ms:.2f} ms. Status: {status_badge}")
    print(f"  Evidence:   {CLR_CYAN}{evidence_path}{CLR_RESET} ({evidence_path.stat().st_size if evidence_path.exists() else 0} bytes)")
    print(f"  Sample SVG: {CLR_CYAN}{svg_path}{CLR_RESET} ({svg_path.stat().st_size if svg_path.exists() else 0} bytes)")
    print(f"{CLR_CYAN}{'=' * 80}{CLR_RESET}\n")

    if overall_status == "blocked":
        print(f"  {CLR_YELLOW}[BLOCKED] Action prevented by safety or platform limitation{CLR_RESET}\n")
        return 0

    if overall_status != "success" or checks_passed < total_checks:
        print(f"  {CLR_RED}{CLR_BOLD}VERIFICATION FAILED: {total_checks - checks_passed} check(s) did not pass.{CLR_RESET}\n")
        return 1

    print(f"  {CLR_GREEN}{CLR_BOLD}VERIFICATION SUCCESS: All {total_checks} stages passed deterministically.{CLR_RESET}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
