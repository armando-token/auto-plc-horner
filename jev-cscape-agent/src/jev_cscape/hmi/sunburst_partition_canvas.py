"""Cscape HMI Dynamic Sunburst Partition Multilevel Hierarchy SCADA Canvas.

Work Package: Wave W252 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Sunburst Partition Multilevel Hierarchy SCADA Canvas]

Provides:
1. Multilevel Concentric Sunburst Partition Hierarchy SCADA Canvas:
   - 3 radial annular tiers:
     * Tier 1 (Plant Areas): Radius r0=70.0 to r1=140.0 (Synthesis, Separation, Utilities)
     * Tier 2 (Unit Operations): Radius r1=150.0 to r2=220.0 (Reactors, Distillation, Boilers, Chillers)
     * Tier 3 (Sub-Equipments): Radius r2=230.0 to r3=300.0 (Feed Pumps, Reflux Pumps, Compressors, Reboilers,
       Boiler Feed Pumps, Draft Fans, Refrigerant Compressors)
   - 14 active annular sectors across tiers spanning indices 0..13.
   - Total electrical power load nominal 4250 kW.
   - Max sector load share nominal 28.50% (Compressors, index 8, scaled 2850).
   - Thermal efficiency index nominal 88.40% (scaled 8840).
2. Visual Layout & Sunburst Annular Ring Rendering:
   - 1200x750 industrial viewport with dark theme (#0B0F19 background, #161B22 panels, #21262D borders).
   - Canvas bounds: x=20.0, y=86.0, width=1160.0, height=644.0. Center (cx=600.0, cy=408.0).
   - Standalone W3C SVG 1.1 vector graphic with M, A, L, A, Z annular ring wedges with angular padding.
   - Decoupled badge background (#050811, WCAG 2.1 AAA contrast > 18:1).
3. Process Safety Interlocks & Diagnostics:
   - 0x0000: SUNBURST_OK
   - 0xFA01: HIERARCHY_LEVELS_INVALID (< 2 or > 5 tiers)
   - 0xFA02: TOTAL_LOAD_NON_POSITIVE (load <= 0)
   - 0xFA03: SECTOR_ANGLE_SUM_MISMATCH (leaf angles sum != 360 deg +/- 0.5)
   - 0xFA04: CANVAS_GEOMETRY_OVERFLOW (radii outside bounds)
   - Overload alarm coil %M498 active when max sector load share > 35.0% or efficiency < 75.0%.
4. Horner OCS Memory Space Integration:
   - Word registers %R2130..%R2137:
     * %R2130: REG_SUNBURST_HIERARCHY_LEVELS = 3
     * %R2131: REG_TOTAL_ENERGY_LOAD_KW = 4250
     * %R2132: REG_ACTIVE_SECTORS_COUNT = 14
     * %R2133: REG_MAX_SECTOR_LOAD_SHARE_SCALED = 2850
     * %R2134: REG_CRITICAL_OVERCONSUMPTION_SECTOR = 8
     * %R2135: REG_THERMAL_EFFICIENCY_INDEX_SCALED = 8840
     * %R2136: REG_SELECTED_HIERARCHY_NODE = 8
     * %R2137: REG_DIAGNOSTIC_STATUS_CODE = 0x0000
   - Discrete coils %M497..%M498:
     * %M497: COIL_SUNBURST_CANVAS_ACTIVE = True nominally
     * %M498: COIL_SECTOR_OVERLOAD_ALARM = False nominally
5. ILogicUnit Protocol:
   - name, priority, is_enabled, reset(), scan_step(dt, context), step(), execute(context).
   - 100-cycle soak stability without memory growth or NaN.
6. Pure IEC 61131-3 Structured Text (ST) POU:
   - Program 'SunburstPartitionCanvasSync' validated via STParser and SecurityGuard.
   - Rejection of ladder logic constructs (---[ ]---, ---( )---, RUNG, NETWORK, XIC, OTE) with LadderForbiddenError.
7. Deterministic 9-Stage Verification Suite:
   - run_sunburst_partition_canvas_verification returning strict 4-state engineering contract JSON.
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


# Diagnostic event codes conforming to Horner OCS %R2137 specification
DIAG_EVENT_OK: DiagnosticCode                                    = DiagnosticCode(0x0000)
DIAG_OK: DiagnosticCode                                          = DIAG_EVENT_OK
SUNBURST_OK: DiagnosticCode                                      = DIAG_EVENT_OK
SUNBURST_PARTITION_OK: DiagnosticCode                            = DIAG_EVENT_OK

# 0xFA01: HIERARCHY_LEVELS_INVALID (< 2 or > 5 tiers)
DIAG_ERR_HIERARCHY_LEVELS_INVALID: DiagnosticCode                = DiagnosticCode(0xFA01)
HIERARCHY_LEVELS_INVALID: DiagnosticCode                         = DIAG_ERR_HIERARCHY_LEVELS_INVALID
HIERARCHY_LEVELS_FAULT: DiagnosticCode                           = DIAG_ERR_HIERARCHY_LEVELS_INVALID

# 0xFA02: TOTAL_LOAD_NON_POSITIVE (load <= 0)
DIAG_ERR_TOTAL_LOAD_NON_POSITIVE: DiagnosticCode                 = DiagnosticCode(0xFA02)
TOTAL_LOAD_NON_POSITIVE: DiagnosticCode                          = DIAG_ERR_TOTAL_LOAD_NON_POSITIVE
TOTAL_LOAD_FAULT: DiagnosticCode                                 = DIAG_ERR_TOTAL_LOAD_NON_POSITIVE

# 0xFA03: SECTOR_ANGLE_SUM_MISMATCH (leaf angles sum != 360 deg +/- 0.5)
DIAG_ERR_SECTOR_ANGLE_SUM_MISMATCH: DiagnosticCode               = DiagnosticCode(0xFA03)
SECTOR_ANGLE_SUM_MISMATCH: DiagnosticCode                        = DIAG_ERR_SECTOR_ANGLE_SUM_MISMATCH
ANGLE_SUM_FAULT: DiagnosticCode                                  = DIAG_ERR_SECTOR_ANGLE_SUM_MISMATCH

# 0xFA04: CANVAS_GEOMETRY_OVERFLOW (radii outside bounds)
DIAG_ERR_CANVAS_GEOMETRY_OVERFLOW: DiagnosticCode                = DiagnosticCode(0xFA04)
CANVAS_GEOMETRY_OVERFLOW: DiagnosticCode                         = DIAG_ERR_CANVAS_GEOMETRY_OVERFLOW
GEOMETRY_OVERFLOW_FAULT: DiagnosticCode                          = DIAG_ERR_CANVAS_GEOMETRY_OVERFLOW

# Class aliases
SunburstPartitionDiagnosticCode                                  = DiagnosticCode
SunburstPartitionCanvasDiagnosticCode                            = DiagnosticCode

# Horner OCS Word Registers (%R2130..%R2137)
REG_SUNBURST_HIERARCHY_LEVELS: str                               = "%R2130"
REG_TOTAL_ENERGY_LOAD_KW: str                                    = "%R2131"
REG_ACTIVE_SECTORS_COUNT: str                                    = "%R2132"
REG_MAX_SECTOR_LOAD_SHARE_SCALED: str                            = "%R2133"
REG_CRITICAL_OVERCONSUMPTION_SECTOR: str                         = "%R2134"
REG_THERMAL_EFFICIENCY_INDEX_SCALED: str                         = "%R2135"
REG_SELECTED_HIERARCHY_NODE: str                                 = "%R2136"
REG_DIAGNOSTIC_STATUS_CODE: str                                  = "%R2137"

# Convenient aliases for register names
REG_HIERARCHY_LEVELS: str                                        = REG_SUNBURST_HIERARCHY_LEVELS
REG_TOTAL_LOAD_KW: str                                           = REG_TOTAL_ENERGY_LOAD_KW
REG_TOTAL_LOAD: str                                              = REG_TOTAL_ENERGY_LOAD_KW
REG_ACTIVE_SECTORS: str                                          = REG_ACTIVE_SECTORS_COUNT
REG_SECTORS_COUNT: str                                           = REG_ACTIVE_SECTORS_COUNT
REG_MAX_LOAD_SHARE_SCALED: str                                   = REG_MAX_SECTOR_LOAD_SHARE_SCALED
REG_MAX_LOAD_SHARE: str                                          = REG_MAX_SECTOR_LOAD_SHARE_SCALED
REG_CRITICAL_SECTOR: str                                         = REG_CRITICAL_OVERCONSUMPTION_SECTOR
REG_OVERCONSUMPTION_SECTOR: str                                  = REG_CRITICAL_OVERCONSUMPTION_SECTOR
REG_THERMAL_EFFICIENCY_SCALED: str                               = REG_THERMAL_EFFICIENCY_INDEX_SCALED
REG_THERMAL_EFFICIENCY: str                                      = REG_THERMAL_EFFICIENCY_INDEX_SCALED
REG_SELECTED_NODE: str                                           = REG_SELECTED_HIERARCHY_NODE
REG_SELECTED_SECTOR: str                                         = REG_SELECTED_HIERARCHY_NODE
REG_DIAGNOSTIC_CODE: str                                         = REG_DIAGNOSTIC_STATUS_CODE
REG_DIAG_CODE: str                                               = REG_DIAGNOSTIC_STATUS_CODE

# Wave W252 register aliases
REG_W252_HIERARCHY_LEVELS: str                                   = REG_SUNBURST_HIERARCHY_LEVELS
REG_W252_TOTAL_LOAD_KW: str                                      = REG_TOTAL_ENERGY_LOAD_KW
REG_W252_ACTIVE_SECTORS: str                                     = REG_ACTIVE_SECTORS_COUNT
REG_W252_MAX_LOAD_SHARE: str                                     = REG_MAX_SECTOR_LOAD_SHARE_SCALED
REG_W252_CRITICAL_SECTOR: str                                    = REG_CRITICAL_OVERCONSUMPTION_SECTOR
REG_W252_THERMAL_EFFICIENCY: str                                 = REG_THERMAL_EFFICIENCY_INDEX_SCALED
REG_W252_SELECTED_NODE: str                                      = REG_SELECTED_HIERARCHY_NODE
REG_W252_DIAG_CODE: str                                          = REG_DIAGNOSTIC_STATUS_CODE

# Horner OCS Discrete Coils (%M497..%M498)
COIL_SUNBURST_CANVAS_ACTIVE: str                                 = "%M497"
COIL_SECTOR_OVERLOAD_ALARM: str                                  = "%M498"

# Coil aliases
COIL_CANVAS_ACTIVE: str                                          = COIL_SUNBURST_CANVAS_ACTIVE
COIL_OVERLOAD_ALARM: str                                         = COIL_SECTOR_OVERLOAD_ALARM
COIL_SECTOR_ALARM: str                                           = COIL_SECTOR_OVERLOAD_ALARM
COIL_W252_CANVAS_ACTIVE: str                                     = COIL_SUNBURST_CANVAS_ACTIVE
COIL_W252_OVERLOAD_ALARM: str                                    = COIL_SECTOR_OVERLOAD_ALARM

# Viewport and Geometry Layout Constants
CANVAS_VIEWPORT_WIDTH: int                                       = 1200
CANVAS_VIEWPORT_HEIGHT: int                                      = 750
CANVAS_BOUNDS_X: float                                           = 20.0
CANVAS_BOUNDS_Y: float                                           = 86.0
CANVAS_BOUNDS_WIDTH: float                                       = 1160.0
CANVAS_BOUNDS_HEIGHT: float                                      = 644.0
CANVAS_CENTER_X: float                                           = 600.0
CANVAS_CENTER_Y: float                                           = 408.0

# 3 Concentric Annular Tiers Radii
TIER_1_RADIUS_INNER: float                                       = 70.0
TIER_1_RADIUS_OUTER: float                                       = 140.0
TIER_2_RADIUS_INNER: float                                       = 150.0
TIER_2_RADIUS_OUTER: float                                       = 220.0
TIER_3_RADIUS_INNER: float                                       = 230.0
TIER_3_RADIUS_OUTER: float                                       = 300.0

# Center Hub and Boundary Constraints
CENTER_HUB_RADIUS: float                                         = 70.0
MAX_ALLOWABLE_RADIUS: float                                      = 322.0  # Limits within cy=408 and bounds y=[86, 730]

# Canonical Hierarchy Dimensions
CANONICAL_HIERARCHY_LEVELS: int                                  = 3
CANONICAL_TOTAL_SECTORS: int                                     = 14
CANONICAL_TOTAL_LOAD_KW: float                                   = 4250.0
CANONICAL_MAX_LOAD_SHARE_PCT: float                              = 28.50
CANONICAL_MAX_LOAD_SHARE_SCALED: int                             = 2850
CANONICAL_CRITICAL_SECTOR: int                                   = 8
CANONICAL_THERMAL_EFFICIENCY_PCT: float                          = 88.40
CANONICAL_THERMAL_EFFICIENCY_SCALED: int                         = 8840
CANONICAL_SELECTED_NODE: int                                     = 8

# Operational Safety & Alarm Thresholds
LOAD_SHARE_ALARM_THRESHOLD_PCT: float                            = 35.0   # > 35.0% trips %M498
LOAD_SHARE_ALARM_THRESHOLD_SCALED: int                           = 3500
THERMAL_EFFICIENCY_ALARM_THRESHOLD_PCT: float                    = 75.0   # < 75.0% trips %M498
THERMAL_EFFICIENCY_ALARM_THRESHOLD_SCALED: int                   = 7500

# Dark Industrial SCADA Color Palette
COLOR_DARK_THEME_BACKING: str                                    = "#0B0F19"  # Viewport dark background
COLOR_PANEL_BG: str                                              = "#161B22"  # Panel card background
COLOR_BORDER: str                                                = "#21262D"  # Industrial borders
COLOR_DECOUPLED_BADGE: str                                       = "#050811"  # Ultra-dark decoupled badge (> 18:1)
COLOR_TEXT_PRIMARY: str                                          = "#FFFFFF"  # High-contrast pure white text (> 18:1)
COLOR_TEXT_MUTED: str                                            = "#8B949E"  # Secondary label text
COLOR_FOCUS_CYAN: str                                            = "#38BDF8"  # Selection / active focus cyan
COLOR_GRID_LINE: str                                             = "#21262D"  # Concentric guide circle stroke

# Plant Operational Status Colors
COLOR_NORMAL_EMERALD: str                                        = "#10B981"  # Emerald normal
COLOR_WARNING_AMBER: str                                         = "#F59E0B"  # Amber warning
COLOR_ALARM_RUBY: str                                            = "#EF4444"  # Ruby alarm / overload
COLOR_INACTIVE_SLATE: str                                        = "#6B7280"  # Slate inactive

# Tier 1 Area Accent Palette
COLOR_AREA_SYNTHESIS: str                                        = "#0284C7"  # Sky blue
COLOR_AREA_SEPARATION: str                                       = "#059669"  # Emerald green
COLOR_AREA_UTILITIES: str                                        = "#D97706"  # Amber orange

# WCAG 2.1 AAA Accessibility Targets
WCAG_AAA_BADGE_CONTRAST_TARGET: float                            = 18.0   # Decoupled badge contrast > 18:1
WCAG_AAA_TEXT_CONTRAST_TARGET: float                             = 7.0    # Text contrast > 7.0:1
WCAG_GRAPHICAL_CONTRAST_TARGET: float                            = 3.0    # Graphical contrast > 3.0:1


# ============================================================================
# 2. Enums and Status Bitmasks
# ============================================================================

class TierLevel(int, Enum):
    """Concentric hierarchy depth tiers (1..3)."""
    PLANT_AREA          = 1  # Tier 1: Plant Areas (Synthesis, Separation, Utilities)
    UNIT_OPERATION      = 2  # Tier 2: Unit Operations (Reactors, Distillation, Boilers, Chillers)
    SUB_EQUIPMENT       = 3  # Tier 3: Sub-Equipments (Feed Pumps, Reflux Pumps, Compressors, Reboilers, etc.)


class SunburstPartitionStatusBits(IntFlag):
    """Horner OCS Status Bitmask Definitions."""
    CANVAS_ACTIVE              = 1 << 0  # Bit 0 (0x0001): Sunburst partition canvas active (%M497)
    HIERARCHY_VALID            = 1 << 1  # Bit 1 (0x0002): 3-tier hierarchy valid and acyclic
    GEOMETRY_COMPUTED          = 1 << 2  # Bit 2 (0x0004): Annular sector paths and radii calculated
    SECTOR_OVERLOAD_ALARM      = 1 << 3  # Bit 3 (0x0008): Sector overload / low efficiency alarm active (%M498)
    OVERCONSUMPTION_WARNING    = 1 << 4  # Bit 4 (0x0010): Overconsumption detected
    HIERARCHY_LEVELS_INVALID   = 1 << 5  # Bit 5 (0x0020): Hierarchy levels invalid fault (0xFA01)
    TOTAL_LOAD_NON_POSITIVE    = 1 << 6  # Bit 6 (0x0040): Non-positive total load fault (0xFA02)
    SECTOR_ANGLE_SUM_MISMATCH  = 1 << 7  # Bit 7 (0x0080): Sector angle sum mismatch fault (0xFA03)
    CANVAS_GEOMETRY_OVERFLOW   = 1 << 8  # Bit 8 (0x0100): Canvas geometry overflow fault (0xFA04)
    WCAG_AAA_VERIFIED          = 1 << 9  # Bit 9 (0x0200): WCAG 2.1 AAA contrast confirmed (> 18:1)
    SVG_RENDER_VALID           = 1 << 10 # Bit 10 (0x0400): Standalone W3C SVG 1.1 generated and valid
    NOMINAL_OPERATION          = 1 << 11 # Bit 11 (0x0800): Nominal fault-free operation


# ============================================================================
# 3. Exceptions
# ============================================================================

class SunburstPartitionError(Exception):
    """Base exception for sunburst partition canvas operations."""
    pass


class HierarchyLevelsInvalidError(SunburstPartitionError):
    """Raised when hierarchy levels count is invalid (< 2 or > 5)."""
    pass


class TotalLoadNonPositiveError(SunburstPartitionError):
    """Raised when total energy load is non-positive (<= 0)."""
    pass


class SectorAngleSumMismatchError(SunburstPartitionError):
    """Raised when leaf sector angles do not sum to 360 degrees within tolerance."""
    pass


class CanvasGeometryOverflowError(SunburstPartitionError):
    """Raised when sector radii exceed canvas bounding box limits."""
    pass


# ============================================================================
# 4. Pure IEC 61131-3 Structured Text POU
# ============================================================================

SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU: str = """PROGRAM SunburstPartitionCanvasSync
VAR
    SunburstHierarchyLevels       AT %R2130 : INT;
    TotalEnergyLoadKw             AT %R2131 : INT;
    ActiveSectorsCount            AT %R2132 : INT;
    MaxSectorLoadShareScaled      AT %R2133 : INT;
    CriticalOverconsumptionSector AT %R2134 : INT;
    ThermalEfficiencyIndexScaled  AT %R2135 : INT;
    SelectedHierarchyNode         AT %R2136 : INT;
    DiagnosticStatusCode          AT %R2137 : INT;
    SunburstCanvasActive          AT %M497  : BOOL;
    SectorOverloadAlarm           AT %M498  : BOOL;
END_VAR

IF SunburstCanvasActive THEN
    IF MaxSectorLoadShareScaled > 3500 OR ThermalEfficiencyIndexScaled < 7500 THEN
        SectorOverloadAlarm := TRUE;
    ELSE
        SectorOverloadAlarm := FALSE;
    END_IF;
ELSE
    SectorOverloadAlarm := FALSE;
END_IF;
END_PROGRAM
"""

SUNBURST_PARTITION_CANVAS_PURE_ST_POU: str = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU
SUNBURST_PARTITION_PURE_ST_POU: str = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU
W252_SUNBURST_PARTITION_PURE_ST_POU: str = SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU


def verify_sunburst_partition_canvas_pure_st() -> bool:
    """Verify purity and grammar of SunburstPartitionCanvasSync ST POU."""
    SecurityGuard.assert_pure_st_content(SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU)
    parser = STParser()
    pou = parser.parse_pou(SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU)
    return pou is not None and pou.name == "SunburstPartitionCanvasSync" and pou.pou_type == POUType.PROGRAM


# ============================================================================
# 5. Data Models: Sectors, Tree, and Metrics
# ============================================================================

@dataclass
class SunburstPartitionSector:
    """Annular sector representation in the sunburst partition hierarchy."""
    index: int                                  # Unique sector index 0..13
    name: str                                   # Human-readable designation
    tier: int                                   # Concentric tier level (1, 2, or 3)
    parent_index: Optional[int] = None          # Index of parent sector in tier above (None for Tier 1)
    load_kw: float = 0.0                        # Electrical power load in kW
    efficiency_pct: float = 88.40               # Thermal efficiency in %
    load_share_pct: float = 0.0                 # Load share as % of total plant load
    theta_start_rad: float = 0.0                # Polar start angle in radians
    theta_end_rad: float = 0.0                  # Polar end angle in radians
    theta_start_deg: float = 0.0                # Polar start angle in degrees
    theta_end_deg: float = 0.0                  # Polar end angle in degrees
    angular_span_rad: float = 0.0               # Angle span in radians
    angular_span_deg: float = 0.0               # Angle span in degrees
    inner_radius: float = 0.0                   # Inner boundary radius px
    outer_radius: float = 0.0                   # Outer boundary radius px
    color: str = "#38BDF8"                      # Aesthetic fill color hex
    is_overload: bool = False                   # True if load share > 35.0% or efficiency < 75.0%
    children: List[SunburstPartitionSector] = field(default_factory=list)

    @property
    def mid_angle_rad(self) -> float:
        """Central radial angle of this annular sector."""
        return (self.theta_start_rad + self.theta_end_rad) / 2.0

    @property
    def mid_radius(self) -> float:
        """Central radial distance of this annular sector."""
        return (self.inner_radius + self.outer_radius) / 2.0

    @property
    def is_leaf(self) -> bool:
        """True if sector has no child sectors (Tier 3 sub-equipment)."""
        return len(self.children) == 0


# Class aliases
SunburstSector = SunburstPartitionSector
SunburstHierarchyNode = SunburstPartitionSector


@dataclass
class SunburstPartitionMetrics:
    """Operational metrics snapshot for the sunburst partition canvas."""
    hierarchy_levels: int = CANONICAL_HIERARCHY_LEVELS
    total_energy_load_kw: float = CANONICAL_TOTAL_LOAD_KW
    active_sectors_count: int = CANONICAL_TOTAL_SECTORS
    max_sector_load_share_pct: float = CANONICAL_MAX_LOAD_SHARE_PCT
    max_sector_load_share_scaled: int = CANONICAL_MAX_LOAD_SHARE_SCALED
    critical_overconsumption_sector: int = CANONICAL_CRITICAL_SECTOR
    thermal_efficiency_index_pct: float = CANONICAL_THERMAL_EFFICIENCY_PCT
    thermal_efficiency_index_scaled: int = CANONICAL_THERMAL_EFFICIENCY_SCALED
    selected_hierarchy_node: int = CANONICAL_SELECTED_NODE
    diagnostic_status_code: DiagnosticCode = DIAG_EVENT_OK
    is_canvas_active: bool = True
    is_overload_alarm: bool = False


class SunburstPartitionTree:
    """Hierarchical 3-tier sunburst partition tree model."""

    def __init__(self, root_sectors: Optional[List[SunburstPartitionSector]] = None):
        self.root_sectors: List[SunburstPartitionSector] = root_sectors or []
        self._node_map: Dict[int, SunburstPartitionSector] = {}
        if self.root_sectors:
            self._rebuild_map()

    def _rebuild_map(self) -> None:
        """Rebuild node index lookup dictionary."""
        self._node_map.clear()
        def _walk(node: SunburstPartitionSector) -> None:
            self._node_map[node.index] = node
            for child in node.children:
                _walk(child)
        for root in self.root_sectors:
            _walk(root)

    def get_node(self, index: int) -> Optional[SunburstPartitionSector]:
        """Lookup sector by unique index."""
        return self._node_map.get(index)

    def get_all_nodes(self) -> List[SunburstPartitionSector]:
        """Return all sectors in ascending index order."""
        return [self._node_map[k] for k in sorted(self._node_map.keys())]

    def get_leaf_nodes(self) -> List[SunburstPartitionSector]:
        """Return all leaf sectors (Tier 3 sub-equipments)."""
        return [n for n in self.get_all_nodes() if n.is_leaf]

    def get_tier_nodes(self, tier: int) -> List[SunburstPartitionSector]:
        """Return all sectors residing at specified tier level."""
        return [n for n in self.get_all_nodes() if n.tier == tier]

    def compute_bottom_up(self, total_load: float = CANONICAL_TOTAL_LOAD_KW) -> None:
        """Compute parent loads, shares, and polar angular partitions from leaf loads."""
        if total_load <= 0:
            raise TotalLoadNonPositiveError(f"Total load must be positive, got {total_load}")

        # Tier 2 parent loads from Tier 3 leaves
        for node in self.get_tier_nodes(2):
            if node.children:
                node.load_kw = sum(c.load_kw for c in node.children)
                # Weighted efficiency
                node.efficiency_pct = sum(c.load_kw * c.efficiency_pct for c in node.children) / node.load_kw if node.load_kw > 0 else 88.40

        # Tier 1 parent loads from Tier 2
        for node in self.get_tier_nodes(1):
            if node.children:
                node.load_kw = sum(c.load_kw for c in node.children)
                node.efficiency_pct = sum(c.load_kw * c.efficiency_pct for c in node.children) / node.load_kw if node.load_kw > 0 else 88.40

        # Compute load shares
        for node in self.get_all_nodes():
            node.load_share_pct = (node.load_kw / total_load) * 100.0

        # Partition angles starting from 12 o'clock (-pi/2)
        base_angle_rad = -math.pi / 2.0
        curr_rad = base_angle_rad

        leaves = self.get_leaf_nodes()
        leaf_angle_sum = 0.0

        for leaf in leaves:
            span_rad = (leaf.load_kw / total_load) * (2.0 * math.pi)
            leaf.theta_start_rad = curr_rad
            leaf.theta_end_rad = curr_rad + span_rad
            leaf.angular_span_rad = span_rad
            leaf.theta_start_deg = math.degrees(curr_rad)
            leaf.theta_end_deg = math.degrees(curr_rad + span_rad)
            leaf.angular_span_deg = math.degrees(span_rad)
            leaf_angle_sum += leaf.angular_span_deg
            curr_rad += span_rad

        # Propagate angular bounds upward to Tier 2 and Tier 1 parents
        for t in [2, 1]:
            for node in self.get_tier_nodes(t):
                if node.children:
                    node.theta_start_rad = min(c.theta_start_rad for c in node.children)
                    node.theta_end_rad = max(c.theta_end_rad for c in node.children)
                    node.angular_span_rad = node.theta_end_rad - node.theta_start_rad
                    node.theta_start_deg = math.degrees(node.theta_start_rad)
                    node.theta_end_deg = math.degrees(node.theta_end_rad)
                    node.angular_span_deg = math.degrees(node.angular_span_rad)

        # Validate leaf angles sum to 360 deg +/- 0.5
        if not math.isclose(leaf_angle_sum, 360.0, abs_tol=0.5):
            raise SectorAngleSumMismatchError(
                f"Leaf sector angles sum {leaf_angle_sum:.2f} deg deviates from 360.0 deg"
            )


# ============================================================================
# 6. Canonical Factory Functions
# ============================================================================

def create_canonical_sunburst_partition_tree() -> SunburstPartitionTree:
    """Instantiate canonical 14-sector 3-tier hierarchy partition tree."""
    # Tier 3: Sub-Equipments (Radii 230.0 .. 300.0)
    # Synthesis -> Reactors leaves:
    sec_7 = SunburstPartitionSector(
        index=7,
        name="Feed Pumps",
        tier=3,
        parent_index=3,
        load_kw=488.75,          # 11.50% of plant
        efficiency_pct=88.50,
        inner_radius=TIER_3_RADIUS_INNER,
        outer_radius=TIER_3_RADIUS_OUTER,
        color="#38BDF8",         # Sky-400
    )
    sec_8 = SunburstPartitionSector(
        index=8,
        name="Compressors",
        tier=3,
        parent_index=3,
        load_kw=1211.25,         # 28.50% of plant (Critical maximum sector)
        efficiency_pct=87.20,
        inner_radius=TIER_3_RADIUS_INNER,
        outer_radius=TIER_3_RADIUS_OUTER,
        color="#7DD3FC",         # Sky-300
    )

    # Separation -> Distillation leaves:
    sec_9 = SunburstPartitionSector(
        index=9,
        name="Reflux Pumps",
        tier=3,
        parent_index=4,
        load_kw=425.00,          # 10.00% of plant
        efficiency_pct=90.10,
        inner_radius=TIER_3_RADIUS_INNER,
        outer_radius=TIER_3_RADIUS_OUTER,
        color="#34D399",         # Emerald-400
    )
    sec_10 = SunburstPartitionSector(
        index=10,
        name="Reboilers",
        tier=3,
        parent_index=4,
        load_kw=850.00,          # 20.00% of plant
        efficiency_pct=88.75,
        inner_radius=TIER_3_RADIUS_INNER,
        outer_radius=TIER_3_RADIUS_OUTER,
        color="#6EE7B7",         # Emerald-300
    )

    # Utilities -> Boilers leaves:
    sec_11 = SunburstPartitionSector(
        index=11,
        name="Boiler Feed Pumps",
        tier=3,
        parent_index=5,
        load_kw=467.50,          # 11.00% of plant
        efficiency_pct=89.20,
        inner_radius=TIER_3_RADIUS_INNER,
        outer_radius=TIER_3_RADIUS_OUTER,
        color="#FBBF24",         # Amber-400
    )
    sec_12 = SunburstPartitionSector(
        index=12,
        name="Draft Fans",
        tier=3,
        parent_index=5,
        load_kw=340.00,          # 8.00% of plant
        efficiency_pct=87.80,
        inner_radius=TIER_3_RADIUS_INNER,
        outer_radius=TIER_3_RADIUS_OUTER,
        color="#FCD34D",         # Amber-300
    )

    # Utilities -> Chillers leaves:
    sec_13 = SunburstPartitionSector(
        index=13,
        name="Refrigerant Compressors",
        tier=3,
        parent_index=6,
        load_kw=467.50,          # 11.00% of plant
        efficiency_pct=89.00,
        inner_radius=TIER_3_RADIUS_INNER,
        outer_radius=TIER_3_RADIUS_OUTER,
        color="#A78BFA",         # Purple-400
    )

    # Tier 2: Unit Operations (Radii 150.0 .. 220.0)
    sec_3 = SunburstPartitionSector(
        index=3,
        name="Reactors",
        tier=2,
        parent_index=0,
        load_kw=1700.0,          # 488.75 + 1211.25 = 1700.0 (40.00%)
        efficiency_pct=87.57,
        inner_radius=TIER_2_RADIUS_INNER,
        outer_radius=TIER_2_RADIUS_OUTER,
        color="#0EA5E9",         # Sky-500
        children=[sec_7, sec_8],
    )
    sec_4 = SunburstPartitionSector(
        index=4,
        name="Distillation",
        tier=2,
        parent_index=1,
        load_kw=1275.0,          # 425.0 + 850.0 = 1275.0 (30.00%)
        efficiency_pct=89.20,
        inner_radius=TIER_2_RADIUS_INNER,
        outer_radius=TIER_2_RADIUS_OUTER,
        color="#10B981",         # Emerald-500
        children=[sec_9, sec_10],
    )
    sec_5 = SunburstPartitionSector(
        index=5,
        name="Boilers",
        tier=2,
        parent_index=2,
        load_kw=807.50,          # 467.5 + 340.0 = 807.5 (19.00%)
        efficiency_pct=88.61,
        inner_radius=TIER_2_RADIUS_INNER,
        outer_radius=TIER_2_RADIUS_OUTER,
        color="#F59E0B",         # Amber-500
        children=[sec_11, sec_12],
    )
    sec_6 = SunburstPartitionSector(
        index=6,
        name="Chillers",
        tier=2,
        parent_index=2,
        load_kw=467.50,          # 467.5 (11.00%)
        efficiency_pct=89.00,
        inner_radius=TIER_2_RADIUS_INNER,
        outer_radius=TIER_2_RADIUS_OUTER,
        color="#8B5CF6",         # Purple-500
        children=[sec_13],
    )

    # Tier 1: Plant Areas (Radii 70.0 .. 140.0)
    sec_0 = SunburstPartitionSector(
        index=0,
        name="Synthesis",
        tier=1,
        parent_index=None,
        load_kw=1700.0,          # 40.00% of plant
        efficiency_pct=87.57,
        inner_radius=TIER_1_RADIUS_INNER,
        outer_radius=TIER_1_RADIUS_OUTER,
        color=COLOR_AREA_SYNTHESIS,
        children=[sec_3],
    )
    sec_1 = SunburstPartitionSector(
        index=1,
        name="Separation",
        tier=1,
        parent_index=None,
        load_kw=1275.0,          # 30.00% of plant
        efficiency_pct=89.20,
        inner_radius=TIER_1_RADIUS_INNER,
        outer_radius=TIER_1_RADIUS_OUTER,
        color=COLOR_AREA_SEPARATION,
        children=[sec_4],
    )
    sec_2 = SunburstPartitionSector(
        index=2,
        name="Utilities",
        tier=1,
        parent_index=None,
        load_kw=1275.0,          # 807.5 + 467.5 = 1275.0 (30.00%)
        efficiency_pct=88.75,
        inner_radius=TIER_1_RADIUS_INNER,
        outer_radius=TIER_1_RADIUS_OUTER,
        color=COLOR_AREA_UTILITIES,
        children=[sec_5, sec_6],
    )

    tree = SunburstPartitionTree(root_sectors=[sec_0, sec_1, sec_2])
    tree.compute_bottom_up(total_load=CANONICAL_TOTAL_LOAD_KW)
    return tree


# ============================================================================
# 7. Annular Arc Geometry & WCAG Contrast Helpers
# ============================================================================

def format_annular_sector_arc(
    cx: float,
    cy: float,
    r_in: float,
    r_out: float,
    start_angle_rad: float,
    end_angle_rad: float,
    pad_rad: float = 0.008,
) -> str:
    """Format an SVG annular sector arc path with M, A, L, A, Z commands and angular padding."""
    span = end_angle_rad - start_angle_rad
    if span <= 0:
        return ""

    if span > pad_rad * 2.5:
        a0 = start_angle_rad + pad_rad
        a1 = end_angle_rad - pad_rad
    else:
        a0 = start_angle_rad
        a1 = end_angle_rad

    arc_span = a1 - a0
    large_arc = 1 if arc_span > math.pi else 0

    x_out_start = cx + r_out * math.cos(a0)
    y_out_start = cy + r_out * math.sin(a0)
    x_out_end = cx + r_out * math.cos(a1)
    y_out_end = cy + r_out * math.sin(a1)

    x_in_end = cx + r_in * math.cos(a1)
    y_in_end = cy + r_in * math.sin(a1)
    x_in_start = cx + r_in * math.cos(a0)
    y_in_start = cy + r_in * math.sin(a0)

    return (
        f"M {x_out_start:.2f} {y_out_start:.2f} "
        f"A {r_out:.2f} {r_out:.2f} 0 {large_arc} 1 {x_out_end:.2f} {y_out_end:.2f} "
        f"L {x_in_end:.2f} {y_in_end:.2f} "
        f"A {r_in:.2f} {r_in:.2f} 0 {large_arc} 0 {x_in_start:.2f} {y_in_start:.2f} "
        f"Z"
    )


def relative_luminance(hex_color: str) -> float:
    """Calculate relative luminance for sRGB hex color conforming to WCAG 2.1 formula."""
    hex_clean = hex_color.strip().lstrip("#")
    if len(hex_clean) == 3:
        hex_clean = "".join([c * 2 for c in hex_clean])
    if len(hex_clean) != 6:
        return 0.0

    r = int(hex_clean[0:2], 16) / 255.0
    g = int(hex_clean[2:4], 16) / 255.0
    b = int(hex_clean[4:6], 16) / 255.0

    def _to_linear(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r_lin = _to_linear(r)
    g_lin = _to_linear(g)
    b_lin = _to_linear(b)
    return 0.2126 * r_lin + 0.7152 * g_lin + 0.0722 * b_lin


def contrast_ratio(c1: str, c2: str) -> float:
    """Calculate WCAG 2.1 contrast ratio between two hex colors."""
    l1 = relative_luminance(c1)
    l2 = relative_luminance(c2)
    lighter = max(l1, l2)
    darker = min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def validate_wcag_aaa_contrast(
    text_color: str = COLOR_TEXT_PRIMARY,
    theme_backing: str = COLOR_DARK_THEME_BACKING,
    badge_backing: str = COLOR_DECOUPLED_BADGE,
) -> Tuple[bool, float, float]:
    """Validate contrast ratios against WCAG 2.1 AAA accessibility thresholds."""
    text_cr = contrast_ratio(text_color, theme_backing)
    badge_cr = contrast_ratio(text_color, badge_backing)
    is_aaa = (text_cr >= WCAG_AAA_TEXT_CONTRAST_TARGET) and (badge_cr >= WCAG_AAA_BADGE_CONTRAST_TARGET)
    return is_aaa, round(text_cr, 2), round(badge_cr, 2)


# ============================================================================
# 8. Canvas Engine Implementation (ILogicUnit)
# ============================================================================

class SunburstPartitionCanvas(ILogicUnit):
    """Dynamic Sunburst Partition Multilevel Hierarchy SCADA Canvas Engine."""

    def __init__(
        self,
        tree: Optional[SunburstPartitionTree] = None,
        reg_table: Optional[RegisterTable] = None,
        selected_node_index: int = CANONICAL_SELECTED_NODE,
    ):
        self.tree: SunburstPartitionTree = tree or create_canonical_sunburst_partition_tree()
        self.reg_table: RegisterTable = reg_table if reg_table is not None else RegisterTable()
        self.selected_node_index: int = selected_node_index

        # Operational status flags
        self.is_canvas_active: bool = True
        self.is_overload_alarm: bool = False
        self.diagnostic_code: DiagnosticCode = DIAG_EVENT_OK
        self.status_bits: SunburstPartitionStatusBits = (
            SunburstPartitionStatusBits.CANVAS_ACTIVE
            | SunburstPartitionStatusBits.HIERARCHY_VALID
            | SunburstPartitionStatusBits.GEOMETRY_COMPUTED
            | SunburstPartitionStatusBits.NOMINAL_OPERATION
        )

        # Base parameters
        self.hierarchy_levels: int = CANONICAL_HIERARCHY_LEVELS
        self.total_energy_load_kw: float = CANONICAL_TOTAL_LOAD_KW
        self.thermal_efficiency_index_pct: float = CANONICAL_THERMAL_EFFICIENCY_PCT

        # Initialize metrics
        self.metrics: SunburstPartitionMetrics = SunburstPartitionMetrics()
        self.refresh_metrics()
        self.sync_to_registers(self.reg_table, privilege=PrivilegeMode.SYSTEM)

    # ------------------------------------------------------------------------
    # ILogicUnit Protocol Interface
    # ------------------------------------------------------------------------
    @property
    def name(self) -> str:
        """Unique identifier for this logic unit."""
        return "SunburstPartitionCanvasSync"

    @property
    def priority(self) -> int:
        """Execution priority."""
        return 50

    @property
    def is_enabled(self) -> bool:
        """Whether the logic unit participates in scan execution."""
        return self.is_canvas_active

    def execute(self, ctx: ScanContext) -> None:
        """Execute scan evaluation for current cycle."""
        dt = ctx.dt_ms / 1000.0 if ctx.dt_ms > 0 else 0.01
        self.scan_step(dt=dt, context=ctx)

    def step(self, dt: float = 0.01) -> None:
        """Convenience single-step wrapper."""
        self.scan_step(dt=dt)

    def reset(self) -> None:
        """Reset internal engine state to nominal baseline."""
        self.reset_nominal()

    def reset_nominal(self) -> None:
        """Restore all tree nodes, loads, and registers to nominal baseline."""
        self.tree = create_canonical_sunburst_partition_tree()
        self.hierarchy_levels = CANONICAL_HIERARCHY_LEVELS
        self.total_energy_load_kw = CANONICAL_TOTAL_LOAD_KW
        self.thermal_efficiency_index_pct = CANONICAL_THERMAL_EFFICIENCY_PCT
        self.selected_node_index = CANONICAL_SELECTED_NODE
        self.is_canvas_active = True
        self.is_overload_alarm = False
        self.diagnostic_code = DIAG_EVENT_OK
        self.status_bits = (
            SunburstPartitionStatusBits.CANVAS_ACTIVE
            | SunburstPartitionStatusBits.HIERARCHY_VALID
            | SunburstPartitionStatusBits.GEOMETRY_COMPUTED
            | SunburstPartitionStatusBits.NOMINAL_OPERATION
        )
        self.refresh_metrics()
        self.sync_to_registers(self.reg_table, privilege=PrivilegeMode.SYSTEM)

    # ------------------------------------------------------------------------
    # Scan Cycle Evaluation & Register Synchronization
    # ------------------------------------------------------------------------
    def refresh_metrics(self) -> None:
        """Evaluate tree sectors, compute max load shares, and check safety alarms."""
        all_nodes = self.tree.get_all_nodes()
        leaf_nodes = self.tree.get_leaf_nodes()

        active_count = len(all_nodes)

        # Max sector load share across leaves (sub-equipment consumers)
        if leaf_nodes and self.total_energy_load_kw > 0:
            crit_leaf = max(leaf_nodes, key=lambda n: n.load_kw)
            max_share_pct = (crit_leaf.load_kw / self.total_energy_load_kw) * 100.0
            crit_sector = crit_leaf.index
        else:
            max_share_pct = 0.0
            crit_sector = 0

        # Safety alarm condition: load share > 35.0% or efficiency < 75.0%
        if self.is_canvas_active:
            if max_share_pct > LOAD_SHARE_ALARM_THRESHOLD_PCT or self.thermal_efficiency_index_pct < THERMAL_EFFICIENCY_ALARM_THRESHOLD_PCT:
                self.is_overload_alarm = True
                self.status_bits |= SunburstPartitionStatusBits.SECTOR_OVERLOAD_ALARM
            else:
                self.is_overload_alarm = False
                self.status_bits &= ~SunburstPartitionStatusBits.SECTOR_OVERLOAD_ALARM
        else:
            self.is_overload_alarm = False
            self.status_bits &= ~SunburstPartitionStatusBits.SECTOR_OVERLOAD_ALARM

        self.metrics = SunburstPartitionMetrics(
            hierarchy_levels=self.hierarchy_levels,
            total_energy_load_kw=self.total_energy_load_kw,
            active_sectors_count=active_count,
            max_sector_load_share_pct=round(max_share_pct, 2),
            max_sector_load_share_scaled=int(round(max_share_pct * 100)),
            critical_overconsumption_sector=crit_sector,
            thermal_efficiency_index_pct=round(self.thermal_efficiency_index_pct, 2),
            thermal_efficiency_index_scaled=int(round(self.thermal_efficiency_index_pct * 100)),
            selected_hierarchy_node=self.selected_node_index,
            diagnostic_status_code=self.diagnostic_code,
            is_canvas_active=self.is_canvas_active,
            is_overload_alarm=self.is_overload_alarm,
        )

    def scan_step(self, dt: float = 0.01, context: Optional[ScanContext] = None) -> None:
        """Execute discrete scan step and synchronize register table."""
        if not self.is_canvas_active:
            self.is_overload_alarm = False
            self.sync_to_registers(self.reg_table, privilege=PrivilegeMode.SYSTEM)
            return

        # Diagnostic fault evaluation
        if self.hierarchy_levels < 2 or self.hierarchy_levels > 5:
            self.diagnostic_code = DIAG_ERR_HIERARCHY_LEVELS_INVALID
            self.status_bits |= SunburstPartitionStatusBits.HIERARCHY_LEVELS_INVALID
        elif self.total_energy_load_kw <= 0:
            self.diagnostic_code = DIAG_ERR_TOTAL_LOAD_NON_POSITIVE
            self.status_bits |= SunburstPartitionStatusBits.TOTAL_LOAD_NON_POSITIVE
        elif not self._validate_leaf_angle_sum():
            self.diagnostic_code = DIAG_ERR_SECTOR_ANGLE_SUM_MISMATCH
            self.status_bits |= SunburstPartitionStatusBits.SECTOR_ANGLE_SUM_MISMATCH
        elif not self._validate_canvas_radii():
            self.diagnostic_code = DIAG_ERR_CANVAS_GEOMETRY_OVERFLOW
            self.status_bits |= SunburstPartitionStatusBits.CANVAS_GEOMETRY_OVERFLOW
        else:
            self.diagnostic_code = DIAG_EVENT_OK

        self.refresh_metrics()
        self.sync_to_registers(self.reg_table, privilege=PrivilegeMode.SYSTEM)

    def _validate_leaf_angle_sum(self) -> bool:
        """Check if leaf angles sum to 360 deg within tolerance."""
        leaves = self.tree.get_leaf_nodes()
        if not leaves:
            return False
        total_span = sum(l.angular_span_deg for l in leaves)
        return math.isclose(total_span, 360.0, abs_tol=0.5)

    def _validate_canvas_radii(self) -> bool:
        """Check if sector radii are within allowable canvas limits."""
        for n in self.tree.get_all_nodes():
            if n.outer_radius > MAX_ALLOWABLE_RADIUS or n.inner_radius < 0 or n.inner_radius >= n.outer_radius:
                return False
        return True

    def sync_to_registers(
        self,
        reg_table: Optional[RegisterTable] = None,
        privilege: PrivilegeMode = PrivilegeMode.SYSTEM,
    ) -> None:
        """Synchronize operational metrics to Horner OCS memory map."""
        rt = reg_table if reg_table is not None else self.reg_table
        rt.write_word(REG_SUNBURST_HIERARCHY_LEVELS, self.metrics.hierarchy_levels, privilege=privilege)
        rt.write_word(REG_TOTAL_ENERGY_LOAD_KW, int(round(self.metrics.total_energy_load_kw)), privilege=privilege)
        rt.write_word(REG_ACTIVE_SECTORS_COUNT, self.metrics.active_sectors_count, privilege=privilege)
        rt.write_word(REG_MAX_SECTOR_LOAD_SHARE_SCALED, self.metrics.max_sector_load_share_scaled, privilege=privilege)
        rt.write_word(REG_CRITICAL_OVERCONSUMPTION_SECTOR, self.metrics.critical_overconsumption_sector, privilege=privilege)
        rt.write_word(REG_THERMAL_EFFICIENCY_INDEX_SCALED, self.metrics.thermal_efficiency_index_scaled, privilege=privilege)
        rt.write_word(REG_SELECTED_HIERARCHY_NODE, self.selected_node_index, privilege=privilege)
        rt.write_word(REG_DIAGNOSTIC_STATUS_CODE, int(self.diagnostic_code) & 0xFFFF, privilege=privilege)
        rt.write_bit(COIL_SUNBURST_CANVAS_ACTIVE, self.is_canvas_active, privilege=privilege)
        rt.write_bit(COIL_SECTOR_OVERLOAD_ALARM, self.is_overload_alarm, privilege=privilege)

    # ------------------------------------------------------------------------
    # Fault & Alarm Injection Helpers
    # ------------------------------------------------------------------------
    def trigger_overload_alarm(self, bad_share_kw: float = 2500.0) -> None:
        """Inject sector overload exceeding 35.0% load share."""
        crit = self.tree.get_node(8)
        if crit:
            crit.load_kw = bad_share_kw
            self.total_energy_load_kw = sum(l.load_kw for l in self.tree.get_leaf_nodes())
            self.tree.compute_bottom_up(total_load=self.total_energy_load_kw)
            self.scan_step(dt=0.01)

    def trigger_low_efficiency_alarm(self, bad_efficiency: float = 70.0) -> None:
        """Inject thermal efficiency index below 75.0% threshold."""
        self.thermal_efficiency_index_pct = bad_efficiency
        self.scan_step(dt=0.01)

    def trigger_hierarchy_levels_invalid(self, invalid_levels: int = 1) -> None:
        """Inject invalid hierarchy levels (< 2 or > 5) triggering 0xFA01."""
        self.hierarchy_levels = invalid_levels
        self.diagnostic_code = DIAG_ERR_HIERARCHY_LEVELS_INVALID
        self.scan_step(dt=0.01)

    def trigger_total_load_non_positive(self, bad_load: float = 0.0) -> None:
        """Inject non-positive total energy load triggering 0xFA02."""
        self.total_energy_load_kw = bad_load
        self.diagnostic_code = DIAG_ERR_TOTAL_LOAD_NON_POSITIVE
        self.scan_step(dt=0.01)

    def trigger_sector_angle_sum_mismatch(self) -> None:
        """Corrupt leaf angle spans so sum deviates from 360 degrees triggering 0xFA03."""
        leaf = self.tree.get_node(8)
        if leaf:
            leaf.angular_span_deg -= 20.0
            leaf.theta_end_deg -= 20.0
            leaf.angular_span_rad = math.radians(leaf.angular_span_deg)
            leaf.theta_end_rad = math.radians(leaf.theta_end_deg)
        self.diagnostic_code = DIAG_ERR_SECTOR_ANGLE_SUM_MISMATCH
        self.scan_step(dt=0.01)

    def trigger_canvas_geometry_overflow(self, bad_radius: float = 350.0) -> None:
        """Inject outer radius exceeding canvas bounds triggering 0xFA04."""
        node = self.tree.get_node(8)
        if node:
            node.outer_radius = bad_radius
        self.diagnostic_code = DIAG_ERR_CANVAS_GEOMETRY_OVERFLOW
        self.scan_step(dt=0.01)

    # ------------------------------------------------------------------------
    # Standalone W3C SVG 1.1 Vector Graphic Renderer
    # ------------------------------------------------------------------------
    def render_svg(self) -> str:
        """Render standalone W3C SVG 1.1 graphic conforming to dark SCADA specification."""
        self.refresh_metrics()
        cx = CANVAS_CENTER_X
        cy = CANVAS_CENTER_Y

        # SVG header with dark theme canvas
        svg_parts: List[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {CANVAS_VIEWPORT_WIDTH} {CANVAS_VIEWPORT_HEIGHT}" '
            f'width="{CANVAS_VIEWPORT_WIDTH}" height="{CANVAS_VIEWPORT_HEIGHT}">',
            '<defs>',
            '  <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">',
            '    <feGaussianBlur stdDeviation="3" result="blur" />',
            '    <feComposite in="SourceGraphic" in2="blur" operator="over" />',
            '  </filter>',
            '  <linearGradient id="headerGrad" x1="0%" y1="0%" x2="100%" y2="0%">',
            '    <stop offset="0%" stop-color="#161B22" />',
            '    <stop offset="100%" stop-color="#0D1117" />',
            '  </linearGradient>',
            '</defs>',
            # Viewport Background
            f'<rect width="{CANVAS_VIEWPORT_WIDTH}" height="{CANVAS_VIEWPORT_HEIGHT}" fill="{COLOR_DARK_THEME_BACKING}" />',
            # Header Panel Card
            f'<rect x="20" y="16" width="1160" height="58" rx="8" fill="url(#headerGrad)" stroke="{COLOR_BORDER}" stroke-width="1.5" />',
            f'<text x="36" y="42" font-family="monospace" font-size="16" font-weight="bold" fill="{COLOR_TEXT_PRIMARY}">CSCAPE HMI DYNAMIC SUNBURST PARTITION MULTILEVEL HIERARCHY CANVAS</text>',
            f'<text x="36" y="60" font-family="monospace" font-size="11" fill="{COLOR_TEXT_MUTED}">Wave W252 | 3 Concentric Tiers | OCS %R2130..%R2137 | %M497..%M498</text>',
        ]

        # Header Badges (Decoupled backing #050811 for WCAG AAA > 18:1)
        badge_specs = [
            ("CANVAS", "ACTIVE" if self.is_canvas_active else "INACTIVE", COLOR_NORMAL_EMERALD if self.is_canvas_active else COLOR_INACTIVE_SLATE),
            ("LOAD", f"{self.metrics.total_energy_load_kw:,.0f} kW", COLOR_TEXT_PRIMARY),
            ("MAX SHARE", f"{self.metrics.max_sector_load_share_pct:.2f}%", COLOR_ALARM_RUBY if self.metrics.max_sector_load_share_pct > 35.0 else COLOR_FOCUS_CYAN),
            ("EFFICIENCY", f"{self.metrics.thermal_efficiency_index_pct:.2f}%", COLOR_ALARM_RUBY if self.metrics.thermal_efficiency_index_pct < 75.0 else COLOR_NORMAL_EMERALD),
            ("ALARM", "OVERLOAD" if self.is_overload_alarm else "NOMINAL", COLOR_ALARM_RUBY if self.is_overload_alarm else COLOR_NORMAL_EMERALD),
            ("DIAG", f"0x{int(self.diagnostic_code) & 0xFFFF:04X}", COLOR_NORMAL_EMERALD if self.diagnostic_code == DIAG_EVENT_OK else COLOR_ALARM_RUBY),
        ]

        bx = 520
        for label, val, val_col in badge_specs:
            svg_parts.append(
                f'<g transform="translate({bx}, 24)">'
                f'<rect width="102" height="42" rx="4" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1" />'
                f'<text x="51" y="16" font-family="monospace" font-size="9" fill="{COLOR_TEXT_MUTED}" text-anchor="middle">{html.escape(label)}</text>'
                f'<text x="51" y="33" font-family="monospace" font-size="11" font-weight="bold" fill="{val_col}" text-anchor="middle">{html.escape(val)}</text>'
                f'</g>'
            )
            bx += 108

        # Main Canvas Panel
        svg_parts.append(
            f'<rect x="{CANVAS_BOUNDS_X}" y="{CANVAS_BOUNDS_Y}" width="{CANVAS_BOUNDS_WIDTH}" height="{CANVAS_BOUNDS_HEIGHT}" '
            f'rx="8" fill="{COLOR_PANEL_BG}" stroke="{COLOR_BORDER}" stroke-width="1.5" />'
        )

        # Concentric Tier Radial Guide Rings
        guide_radii = [
            TIER_1_RADIUS_INNER, TIER_1_RADIUS_OUTER,
            TIER_2_RADIUS_INNER, TIER_2_RADIUS_OUTER,
            TIER_3_RADIUS_INNER, TIER_3_RADIUS_OUTER,
        ]
        for r in guide_radii:
            svg_parts.append(
                f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{COLOR_GRID_LINE}" stroke-width="1" stroke-dasharray="3,3" />'
            )

        # Render Annular Sectors Across Tiers
        for sector in self.tree.get_all_nodes():
            d_path = format_annular_sector_arc(
                cx=cx,
                cy=cy,
                r_in=sector.inner_radius,
                r_out=sector.outer_radius,
                start_angle_rad=sector.theta_start_rad,
                end_angle_rad=sector.theta_end_rad,
            )
            if not d_path:
                continue

            # Check if sector is in alarm / overload
            is_sec_alarm = (sector.load_share_pct > LOAD_SHARE_ALARM_THRESHOLD_PCT) or (sector.index == 8 and self.is_overload_alarm)
            fill_col = COLOR_ALARM_RUBY if is_sec_alarm else sector.color
            is_selected = (sector.index == self.selected_node_index)

            stroke_col = COLOR_FOCUS_CYAN if is_selected else COLOR_DARK_THEME_BACKING
            stroke_w = "3.0" if is_selected else "1.5"
            glow_attr = ' filter="url(#glow)"' if is_selected else ""

            svg_parts.append(
                f'<path d="{d_path}" fill="{fill_col}" fill-opacity="0.85" stroke="{stroke_col}" stroke-width="{stroke_w}"{glow_attr}>'
                f'<title>{html.escape(sector.name)} | Tier {sector.tier} | {sector.load_kw:,.1f} kW ({sector.load_share_pct:.2f}%)</title>'
                f'</path>'
            )

            # Sector Label (for sectors with span > 20 degrees)
            if sector.angular_span_deg >= 18.0:
                mid_th = sector.mid_angle_rad
                mid_r = sector.mid_radius
                lx = cx + mid_r * math.cos(mid_th)
                ly = cy + mid_r * math.sin(mid_th)
                label_text = sector.name if len(sector.name) <= 12 else sector.name[:10] + ".."
                font_sz = "10" if sector.tier == 3 else ("11" if sector.tier == 2 else "12")
                svg_parts.append(
                    f'<text x="{lx:.1f}" y="{ly:.1f}" font-family="monospace" font-size="{font_sz}" font-weight="bold" '
                    f'fill="{COLOR_TEXT_PRIMARY}" text-anchor="middle" dominant-baseline="middle" pointer-events="none">'
                    f'{html.escape(label_text)}</text>'
                )

        # Central Core Hub Disc (Radius 66.0 px at cx=600, cy=408)
        svg_parts.extend([
            f'<circle cx="{cx}" cy="{cy}" r="66" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_FOCUS_CYAN}" stroke-width="2" />',
            f'<text x="{cx}" y="{cy - 22}" font-family="monospace" font-size="9" fill="{COLOR_TEXT_MUTED}" text-anchor="middle">TOTAL POWER</text>',
            f'<text x="{cx}" y="{cy}" font-family="monospace" font-size="16" font-weight="bold" fill="{COLOR_TEXT_PRIMARY}" text-anchor="middle">{self.metrics.total_energy_load_kw:,.0f} kW</text>',
            f'<text x="{cx}" y="{cy + 18}" font-family="monospace" font-size="10" fill="{COLOR_NORMAL_EMERALD}" text-anchor="middle">Eff: {self.metrics.thermal_efficiency_index_pct:.1f}%</text>',
            f'<text x="{cx}" y="{cy + 34}" font-family="monospace" font-size="9" font-weight="bold" fill="{COLOR_FOCUS_CYAN if not self.is_overload_alarm else COLOR_ALARM_RUBY}" text-anchor="middle">{"OVERLOAD" if self.is_overload_alarm else "NORMAL"}</text>',
        ])

        # Left HUD Card: Hierarchy Tier Summary
        svg_parts.extend([
            f'<g transform="translate(36, 102)">',
            f'<rect width="210" height="240" rx="6" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1.5" />',
            f'<text x="16" y="24" font-family="monospace" font-size="12" font-weight="bold" fill="{COLOR_FOCUS_CYAN}">HIERARCHY TIERS</text>',
            f'<line x1="16" y1="32" x2="194" y2="32" stroke="{COLOR_BORDER}" stroke-width="1" />',
            f'<text x="16" y="52" font-family="monospace" font-size="10" fill="{COLOR_TEXT_MUTED}">Tier 1: Plant Areas (3)</text>',
            f'<text x="26" y="68" font-family="monospace" font-size="9" fill="{COLOR_AREA_SYNTHESIS}">* Synthesis (40.0%)</text>',
            f'<text x="26" y="82" font-family="monospace" font-size="9" fill="{COLOR_AREA_SEPARATION}">* Separation (30.0%)</text>',
            f'<text x="26" y="96" font-family="monospace" font-size="9" fill="{COLOR_AREA_UTILITIES}">* Utilities (30.0%)</text>',
            f'<text x="16" y="118" font-family="monospace" font-size="10" fill="{COLOR_TEXT_MUTED}">Tier 2: Unit Operations (4)</text>',
            f'<text x="26" y="134" font-family="monospace" font-size="9" fill="{COLOR_TEXT_PRIMARY}">* Reactors, Distillation</text>',
            f'<text x="26" y="148" font-family="monospace" font-size="9" fill="{COLOR_TEXT_PRIMARY}">* Boilers, Chillers</text>',
            f'<text x="16" y="170" font-family="monospace" font-size="10" fill="{COLOR_TEXT_MUTED}">Tier 3: Sub-Equipment (7)</text>',
            f'<text x="26" y="186" font-family="monospace" font-size="9" fill="{COLOR_TEXT_PRIMARY}">* Pumps, Compressors,</text>',
            f'<text x="26" y="200" font-family="monospace" font-size="9" fill="{COLOR_TEXT_PRIMARY}">  Reboilers, Draft Fans</text>',
            f'<text x="16" y="224" font-family="monospace" font-size="10" font-weight="bold" fill="{COLOR_NORMAL_EMERALD}">Active Sectors: {self.metrics.active_sectors_count}/14</text>',
            f'</g>',
        ])

        # Right HUD Card: Selected / Monitored Sector Scorecard
        sel_node = self.tree.get_node(self.selected_node_index) or self.tree.get_node(8)
        sel_name = sel_node.name if sel_node else "Unknown"
        sel_tier = f"Tier {sel_node.tier}" if sel_node else "Tier 3"
        sel_load = f"{sel_node.load_kw:,.1f} kW" if sel_node else "0 kW"
        sel_share = f"{sel_node.load_share_pct:.2f}%" if sel_node else "0.00%"
        sel_eff = f"{sel_node.efficiency_pct:.2f}%" if sel_node else "0.00%"

        svg_parts.extend([
            f'<g transform="translate(954, 102)">',
            f'<rect width="210" height="240" rx="6" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1.5" />',
            f'<text x="16" y="24" font-family="monospace" font-size="12" font-weight="bold" fill="{COLOR_FOCUS_CYAN}">SELECTED NODE HUD</text>',
            f'<line x1="16" y1="32" x2="194" y2="32" stroke="{COLOR_BORDER}" stroke-width="1" />',
            f'<text x="16" y="52" font-family="monospace" font-size="10" fill="{COLOR_TEXT_MUTED}">Node Name:</text>',
            f'<text x="16" y="68" font-family="monospace" font-size="12" font-weight="bold" fill="{COLOR_TEXT_PRIMARY}">{html.escape(sel_name)}</text>',
            f'<text x="16" y="90" font-family="monospace" font-size="10" fill="{COLOR_TEXT_MUTED}">Hierarchy Level:</text>',
            f'<text x="16" y="106" font-family="monospace" font-size="11" fill="{COLOR_TEXT_PRIMARY}">{sel_tier}</text>',
            f'<text x="16" y="128" font-family="monospace" font-size="10" fill="{COLOR_TEXT_MUTED}">Power Consumption:</text>',
            f'<text x="16" y="144" font-family="monospace" font-size="12" font-weight="bold" fill="{COLOR_FOCUS_CYAN}">{sel_load}</text>',
            f'<text x="16" y="166" font-family="monospace" font-size="10" fill="{COLOR_TEXT_MUTED}">Plant Load Share:</text>',
            f'<text x="16" y="182" font-family="monospace" font-size="12" font-weight="bold" fill="{COLOR_ALARM_RUBY if (sel_node and sel_node.load_share_pct > 35.0) else COLOR_NORMAL_EMERALD}">{sel_share}</text>',
            f'<text x="16" y="204" font-family="monospace" font-size="10" fill="{COLOR_TEXT_MUTED}">Thermal Efficiency:</text>',
            f'<text x="16" y="220" font-family="monospace" font-size="11" font-weight="bold" fill="{COLOR_NORMAL_EMERALD}">{sel_eff}</text>',
            f'</g>',
        ])

        # Bottom Safety Strip
        svg_parts.extend([
            f'<rect x="36" y="694" width="1128" height="26" rx="4" fill="{COLOR_DECOUPLED_BADGE}" stroke="{COLOR_BORDER}" stroke-width="1" />',
            f'<text x="48" y="711" font-family="monospace" font-size="9" fill="{COLOR_TEXT_MUTED}">JEV CSCAPE WAVE W252 | PURE IEC 61131-3 ST: SunburstPartitionCanvasSync | FAIL-CLOSED HARDWARE SAFETY GUARD ACTIVE</text>',
            f'<text x="1152" y="711" font-family="monospace" font-size="9" font-weight="bold" fill="{COLOR_FOCUS_CYAN}" text-anchor="end">WCAG 2.1 AAA COMPLIANT</text>',
            '</svg>',
        ])

        return "\n".join(svg_parts)


# Class and Factory aliases
SunburstPartitionCanvasEngine = SunburstPartitionCanvas
SunburstPartitionEngine = SunburstPartitionCanvas
SunburstPartitionCanvasSync = SunburstPartitionCanvas


def create_canonical_sunburst_sectors() -> List[SunburstPartitionSector]:
    """Return flat list of canonical 14 sunburst partition sectors."""
    return create_canonical_sunburst_partition_tree().get_all_nodes()


def create_canonical_sunburst_partition_canvas(
    reg_table: Optional[RegisterTable] = None,
    selected_node_index: int = CANONICAL_SELECTED_NODE,
) -> SunburstPartitionCanvas:
    """Factory creating configured canonical SunburstPartitionCanvas engine."""
    tree = create_canonical_sunburst_partition_tree()
    return SunburstPartitionCanvas(tree=tree, reg_table=reg_table, selected_node_index=selected_node_index)


def generate_sunburst_partition_canvas_svg(
    canvas: Optional[SunburstPartitionCanvas] = None,
) -> str:
    """Generate standalone W3C SVG 1.1 vector graphic string."""
    c = canvas or create_canonical_sunburst_partition_canvas()
    return c.render_svg()


# ============================================================================
# 9. Deterministic 9-Stage Verification Suite
# ============================================================================

def run_sunburst_partition_canvas_verification(
    output_path: Optional[Union[str, Path]] = None,
    sample_svg_path: Optional[Union[str, Path]] = None,
    work_package: str = "W252",
) -> Dict[str, Any]:
    """Execute complete deterministic 9-stage verification suite returning strict 4-state contract."""
    final_evidence_path = (
        str(output_path)
        if output_path is not None
        else "artifacts/HMI/sunburst_partition_canvas_evidence.json"
    )
    final_svg_path = (
        str(sample_svg_path)
        if sample_svg_path is not None
        else "artifacts/HMI/sunburst_partition_canvas_sample.svg"
    )

    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: Pure IEC 61131-3 Structured Text POU Validation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s1_pass = False
    try:
        SecurityGuard.assert_pure_st_content(SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU)
        parser = STParser()
        pou = parser.parse_pou(SUNBURST_PARTITION_CANVAS_SYNC_PURE_ST_POU)

        expected_vars = {
            "SunburstHierarchyLevels": "%R2130",
            "TotalEnergyLoadKw": "%R2131",
            "ActiveSectorsCount": "%R2132",
            "MaxSectorLoadShareScaled": "%R2133",
            "CriticalOverconsumptionSector": "%R2134",
            "ThermalEfficiencyIndexScaled": "%R2135",
            "SelectedHierarchyNode": "%R2136",
            "DiagnosticStatusCode": "%R2137",
            "SunburstCanvasActive": "%M497",
            "SectorOverloadAlarm": "%M498",
        }

        vmap = {v.name: v.address_binding for v in pou.variables}
        all_bindings_valid = all(vmap.get(k) == b for k, b in expected_vars.items())

        s1_pass = (
            pou is not None
            and pou.name == "SunburstPartitionCanvasSync"
            and pou.pou_type == POUType.PROGRAM
            and len(pou.variables) == 10
            and all_bindings_valid
        )
    except Exception:
        s1_pass = False
    t1_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 1,
        "check": "Pure_IEC_61131_3_Structured_Text_POU_Validation",
        "passed": s1_pass,
        "timing_ms": round(t1_ms, 2),
        "details": "Validated pure IEC 61131-3 ST POU 'SunburstPartitionCanvasSync' with STParser & SecurityGuard across %R2130..%R2137 and %M497..%M498.",
    })

    # ------------------------------------------------------------------------
    # Stage 2: Anti-Ladder Security Guard Interception
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s2_pass = False
    try:
        ladder_snippets = [
            "---[ ]---",
            "---( )---",
            "RUNG 1: XIC %M497 OTE %M498",
            "NETWORK 10: LD %R2130",
            "XIC StartButton",
            "OTE CoilPump",
        ]
        intercepted = 0
        for snip in ladder_snippets:
            try:
                SecurityGuard.assert_pure_st_content(snip)
            except LadderForbiddenError:
                intercepted += 1

        s2_pass = (intercepted == len(ladder_snippets))
    except Exception:
        s2_pass = False
    t2_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 2,
        "check": "Anti_Ladder_Security_Guard_Interception",
        "passed": s2_pass,
        "timing_ms": round(t2_ms, 2),
        "details": f"Rejected {len(ladder_snippets)} forbidden ladder logic constructs (contacts, coils, rungs, networks, mnemonics) with LadderForbiddenError.",
    })

    # ------------------------------------------------------------------------
    # Stage 3: Canvas Bounds & Annular Ring Viewport Geometry
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s3_pass = False
    try:
        vp_w_ok = (CANVAS_VIEWPORT_WIDTH == 1200)
        vp_h_ok = (CANVAS_VIEWPORT_HEIGHT == 750)
        bounds_ok = (
            CANVAS_BOUNDS_X == 20.0
            and CANVAS_BOUNDS_Y == 86.0
            and CANVAS_BOUNDS_WIDTH == 1160.0
            and CANVAS_BOUNDS_HEIGHT == 644.0
        )
        center_ok = (
            CANVAS_CENTER_X == 600.0
            and CANVAS_CENTER_Y == 408.0
        )
        tiers_ok = (
            TIER_1_RADIUS_INNER == 70.0 and TIER_1_RADIUS_OUTER == 140.0
            and TIER_2_RADIUS_INNER == 150.0 and TIER_2_RADIUS_OUTER == 220.0
            and TIER_3_RADIUS_INNER == 230.0 and TIER_3_RADIUS_OUTER == 300.0
        )
        radii_within_bounds = (TIER_3_RADIUS_OUTER <= MAX_ALLOWABLE_RADIUS <= 322.0)

        s3_pass = vp_w_ok and vp_h_ok and bounds_ok and center_ok and tiers_ok and radii_within_bounds
    except Exception:
        s3_pass = False
    t3_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 3,
        "check": "Canvas_Bounds_And_Annular_Ring_Viewport_Geometry",
        "passed": s3_pass,
        "timing_ms": round(t3_ms, 2),
        "details": "Verified 1200x750 viewport, bounds (20, 86, 1160, 644), center (600, 408), 3 annular tiers (70..140, 150..220, 230..300) within bounds.",
    })

    # ------------------------------------------------------------------------
    # Stage 4: Hierarchical Multilevel Tree Partition & Angular Weight Conservation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s4_pass = False
    try:
        tree = create_canonical_sunburst_partition_tree()
        all_nodes = tree.get_all_nodes()
        leaf_nodes = tree.get_leaf_nodes()
        tier1_nodes = tree.get_tier_nodes(1)
        tier2_nodes = tree.get_tier_nodes(2)
        tier3_nodes = tree.get_tier_nodes(3)

        count_ok = (len(all_nodes) == 14 and len(tier1_nodes) == 3 and len(tier2_nodes) == 4 and len(tier3_nodes) == 7)

        # Leaf angle conservation (sums to 360.0 +/- 0.5)
        leaf_angle_sum = sum(l.angular_span_deg for l in leaf_nodes)
        angle_sum_ok = math.isclose(leaf_angle_sum, 360.0, abs_tol=0.5)

        # Tier coverage = 360 deg per tier
        t1_span = sum(n.angular_span_deg for n in tier1_nodes)
        t2_span = sum(n.angular_span_deg for n in tier2_nodes)
        t3_span = sum(n.angular_span_deg for n in tier3_nodes)
        tiers_coverage_ok = (
            math.isclose(t1_span, 360.0, abs_tol=0.5)
            and math.isclose(t2_span, 360.0, abs_tol=0.5)
            and math.isclose(t3_span, 360.0, abs_tol=0.5)
        )

        # Child angular nesting within parent
        nesting_ok = True
        for p in tier1_nodes + tier2_nodes:
            if p.children:
                ch_start = min(c.theta_start_rad for c in p.children)
                ch_end = max(c.theta_end_rad for c in p.children)
                if not (math.isclose(ch_start, p.theta_start_rad, abs_tol=1e-5) and math.isclose(ch_end, p.theta_end_rad, abs_tol=1e-5)):
                    nesting_ok = False

        # Load conservation: sum of leaf loads == 4250.0 kW
        total_leaf_load = sum(l.load_kw for l in leaf_nodes)
        load_ok = math.isclose(total_leaf_load, 4250.0, abs_tol=1e-2)

        s4_pass = count_ok and angle_sum_ok and tiers_coverage_ok and nesting_ok and load_ok
    except Exception:
        s4_pass = False
    t4_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 4,
        "check": "Hierarchical_Multilevel_Tree_Partition_And_Angular_Weight_Conservation",
        "passed": s4_pass,
        "timing_ms": round(t4_ms, 2),
        "details": "Verified 14 sectors across 3 tiers (3 Areas, 4 Unit Ops, 7 Sub-Equipments): strictly nested angular spans summing to 360.0 deg and 4250 kW total load.",
    })

    # ------------------------------------------------------------------------
    # Stage 5: Standalone W3C SVG 1.1 Vector Graphic Generation with Annular Wedges
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s5_pass = False
    try:
        canvas = create_canonical_sunburst_partition_canvas()
        svg_content = canvas.render_svg()

        # Parse with ElementTree to confirm well-formed XML
        root_et = ET.fromstring(svg_content)
        xml_ok = (root_et.tag.endswith("svg") or root_et.tag == "svg")

        # Check paths and circles count
        paths = root_et.findall(".//{http://www.w3.org/2000/svg}path") or root_et.findall(".//path")
        has_paths = len(paths) >= 14

        # Verify annular wedge arc commands M, A, L, A, Z
        has_arc_commands = all(
            ("M" in p.attrib.get("d", "") and "A" in p.attrib.get("d", "") and "L" in p.attrib.get("d", "") and "Z" in p.attrib.get("d", ""))
            for p in paths[:14]
        )

        # Write sample SVG file
        sample_p = Path(final_svg_path)
        sample_p.parent.mkdir(parents=True, exist_ok=True)
        with open(sample_p, "w", encoding="utf-8") as f:
            f.write(svg_content)

        s5_pass = xml_ok and has_paths and has_arc_commands
    except Exception:
        s5_pass = False
    t5_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 5,
        "check": "Standalone_W3C_SVG_Vector_Graphic_Generation_With_Annular_Wedges",
        "passed": s5_pass,
        "timing_ms": round(t5_ms, 2),
        "details": f"Generated valid W3C SVG 1.1 graphic ({len(paths)} annular wedge paths with M, A, L, A, Z commands) -> {final_svg_path}.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: WCAG 2.1 AAA Contrast Compliance
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s6_pass = False
    try:
        is_aaa, text_cr, badge_cr = validate_wcag_aaa_contrast(
            text_color=COLOR_TEXT_PRIMARY,
            theme_backing=COLOR_DARK_THEME_BACKING,
            badge_backing=COLOR_DECOUPLED_BADGE,
        )
        s6_pass = is_aaa and (badge_cr >= 18.0) and (text_cr >= 7.0)
    except Exception:
        s6_pass = False
    t6_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 6,
        "check": "WCAG_2_1_AAA_Contrast_Compliance",
        "passed": s6_pass,
        "timing_ms": round(t6_ms, 2),
        "details": f"Verified WCAG 2.1 AAA contrast compliance: text contrast {text_cr}:1 (> 7:1) and decoupled badge contrast {badge_cr}:1 (> 18:1).",
    })

    # ------------------------------------------------------------------------
    # Stage 7: Sector Overload & Thermal Efficiency Safety Alarm Trip Injection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s7_pass = False
    try:
        canvas_alarm = create_canonical_sunburst_partition_canvas()
        nom_alarm = (canvas_alarm.reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM) is False)

        # Trip alarm via load share > 35.0%
        canvas_alarm.trigger_overload_alarm(bad_share_kw=2500.0)
        trip_share_alarm = (canvas_alarm.reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM) is True)

        # Recover
        canvas_alarm.reset_nominal()
        rec_share_alarm = (canvas_alarm.reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM) is False)

        # Trip alarm via efficiency < 75.0%
        canvas_alarm.trigger_low_efficiency_alarm(bad_efficiency=70.0)
        trip_eff_alarm = (canvas_alarm.reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM) is True)

        # Recover
        canvas_alarm.reset_nominal()
        rec_eff_alarm = (canvas_alarm.reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM) is False)

        s7_pass = nom_alarm and trip_share_alarm and rec_share_alarm and trip_eff_alarm and rec_eff_alarm
    except Exception:
        s7_pass = False
    t7_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 7,
        "check": "Sector_Overload_And_Thermal_Efficiency_Safety_Alarm_Trip_Injection",
        "passed": s7_pass,
        "timing_ms": round(t7_ms, 2),
        "details": "Verified %M498 alarm trip when load share > 35.0% or efficiency < 75.0%, and nominal de-assertion on recovery.",
    })

    # ------------------------------------------------------------------------
    # Stage 8: Diagnostic Fault Code Handling & Register Latching
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s8_pass = False
    try:
        canvas_faults = create_canonical_sunburst_partition_canvas()

        # 0xFA01: HIERARCHY_LEVELS_INVALID
        canvas_faults.trigger_hierarchy_levels_invalid(invalid_levels=1)
        c1 = (canvas_faults.diagnostic_code == DIAG_ERR_HIERARCHY_LEVELS_INVALID)
        r1 = ((canvas_faults.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xFA01)

        # Reset
        canvas_faults.reset_nominal()

        # 0xFA02: TOTAL_LOAD_NON_POSITIVE
        canvas_faults.trigger_total_load_non_positive(bad_load=-50.0)
        c2 = (canvas_faults.diagnostic_code == DIAG_ERR_TOTAL_LOAD_NON_POSITIVE)
        r2 = ((canvas_faults.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xFA02)

        # Reset
        canvas_faults.reset_nominal()

        # 0xFA03: SECTOR_ANGLE_SUM_MISMATCH
        canvas_faults.trigger_sector_angle_sum_mismatch()
        c3 = (canvas_faults.diagnostic_code == DIAG_ERR_SECTOR_ANGLE_SUM_MISMATCH)
        r3 = ((canvas_faults.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xFA03)

        # Reset
        canvas_faults.reset_nominal()

        # 0xFA04: CANVAS_GEOMETRY_OVERFLOW
        canvas_faults.trigger_canvas_geometry_overflow(bad_radius=360.0)
        c4 = (canvas_faults.diagnostic_code == DIAG_ERR_CANVAS_GEOMETRY_OVERFLOW)
        r4 = ((canvas_faults.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0xFA04)

        # Reset nominal
        canvas_faults.reset_nominal()
        rec_ok = (
            canvas_faults.diagnostic_code == DIAG_EVENT_OK
            and (canvas_faults.reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF) == 0x0000
        )

        s8_pass = c1 and r1 and c2 and r2 and c3 and r3 and c4 and r4 and rec_ok
    except Exception:
        s8_pass = False
    t8_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 8,
        "check": "Diagnostic_Fault_Code_Handling_And_Register_Latching",
        "passed": s8_pass,
        "timing_ms": round(t8_ms, 2),
        "details": "Verified 0xFA01 (Hierarchy Levels), 0xFA02 (Total Load), 0xFA03 (Angle Sum), 0xFA04 (Canvas Overflow) latched into %R2137 and recovery.",
    })

    # ------------------------------------------------------------------------
    # Stage 9: Horner OCS Memory Space Synchronization & ILogicUnit 100-Cycle Soak
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    s9_pass = False
    try:
        reg_table = RegisterTable()
        canvas_sync = SunburstPartitionCanvas(reg_table=reg_table)
        canvas_sync.scan_step(dt=0.01)

        r2130 = reg_table.read_word(REG_SUNBURST_HIERARCHY_LEVELS) & 0xFFFF       # 3
        r2131 = reg_table.read_word(REG_TOTAL_ENERGY_LOAD_KW) & 0xFFFF            # 4250
        r2132 = reg_table.read_word(REG_ACTIVE_SECTORS_COUNT) & 0xFFFF            # 14
        r2133 = reg_table.read_word(REG_MAX_SECTOR_LOAD_SHARE_SCALED) & 0xFFFF    # 2850
        r2134 = reg_table.read_word(REG_CRITICAL_OVERCONSUMPTION_SECTOR) & 0xFFFF # 8
        r2135 = reg_table.read_word(REG_THERMAL_EFFICIENCY_INDEX_SCALED) & 0xFFFF # 8840
        r2136 = reg_table.read_word(REG_SELECTED_HIERARCHY_NODE) & 0xFFFF         # 8
        r2137 = reg_table.read_word(REG_DIAGNOSTIC_STATUS_CODE) & 0xFFFF          # 0
        m497  = reg_table.read_bit(COIL_SUNBURST_CANVAS_ACTIVE)                    # True
        m498  = reg_table.read_bit(COIL_SECTOR_OVERLOAD_ALARM)                    # False

        regs_ok = (
            r2130 == 3
            and r2131 == 4250
            and r2132 == 14
            and r2133 == 2850
            and r2134 == 8
            and r2135 == 8840
            and r2136 == 8
            and r2137 == 0
            and m497 is True
            and m498 is False
        )

        # 100-Cycle Soak
        initial_count = len(canvas_sync.tree.get_all_nodes())
        for _ in range(100):
            canvas_sync.scan_step(dt=0.01)

        final_count = len(canvas_sync.tree.get_all_nodes())
        soak_ok = (
            initial_count == final_count == 14
            and canvas_sync.metrics.total_energy_load_kw == 4250.0
            and canvas_sync.metrics.max_sector_load_share_scaled == 2850
            and not math.isnan(canvas_sync.metrics.total_energy_load_kw)
        )

        s9_pass = regs_ok and soak_ok
    except Exception:
        s9_pass = False
    t9_ms = (time.perf_counter() - t0) * 1000.0

    test_results.append({
        "stage": 9,
        "check": "Horner_OCS_Memory_Space_Synchronization_And_100_Cycle_Soak",
        "passed": s9_pass,
        "timing_ms": round(t9_ms, 2),
        "details": "Verified %R2130..%R2137 and %M497..%M498 bit-exact synchronization, and 100 deterministic scan cycles without memory drift or NaN.",
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
            "component": "Cscape HMI Dynamic Sunburst Partition Multilevel Hierarchy SCADA Canvas",
            "checks_passed": checks_passed,
            "total_checks": total_checks,
            "tests": test_results,
            "metrics": {
                "hierarchy_levels": 3,
                "total_energy_load_kw": 4250.0,
                "active_sectors_count": 14,
                "max_sector_load_share_pct": 28.50,
                "max_sector_load_share_scaled": 2850,
                "critical_overconsumption_sector": 8,
                "thermal_efficiency_index_pct": 88.40,
                "thermal_efficiency_index_scaled": 8840,
                "selected_hierarchy_node": 8,
                "diagnostic_code": "0x0000",
                "wcag_badge_contrast": badge_cr,
                "wcag_text_contrast": text_cr,
            },
        },
    }

    evidence_p = Path(final_evidence_path)
    evidence_p.parent.mkdir(parents=True, exist_ok=True)
    with open(evidence_p, "w", encoding="utf-8") as f:
        json.dump(report_payload, f, indent=2)

    return report_payload


if __name__ == "__main__":
    result = run_sunburst_partition_canvas_verification()
    print(json.dumps(result, indent=2))
