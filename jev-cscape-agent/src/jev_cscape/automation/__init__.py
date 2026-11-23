"""Automation package for JEV Cscape Agent."""

from .lifecycle import CscapeLifecycleController
from .launcher import CscapeLauncher
from .dialog_sweeper import DialogSweeper, DialogType, DiscoveredDialog, DismissalRecord, SweepReport
from .navigation_map import NavigationMap, NavCommand, DockingPane, CommandSafety
from .stability import StabilityGuardian, ProcessHealthSnapshot, StabilityBenchmark
from .p1_selection import P1FieldSelector, ControllerSeries, IOModelProfile, ControllerTargetProfile
from .channel_matrix import ChannelMatrix, ChannelAccess, ChannelType, ParsedRegister
from .gui_controller import GUIBoundaryController, LockStatus
from .compiler import CscapeCompilerDispatcher, CompilationResult
from .output_scraper import (
    CscapeOutputScraper,
    DiagnosticSeverity,
    OutputDiagnostic,
    ScraperReport,
)

__all__ = [
    "CscapeLifecycleController",
    "CscapeLauncher",
    "DialogSweeper",
    "DialogType",
    "DiscoveredDialog",
    "DismissalRecord",
    "SweepReport",
    "NavigationMap",
    "NavCommand",
    "DockingPane",
    "CommandSafety",
    "StabilityGuardian",
    "ProcessHealthSnapshot",
    "StabilityBenchmark",
    "P1FieldSelector",
    "ControllerSeries",
    "IOModelProfile",
    "ControllerTargetProfile",
    "ChannelMatrix",
    "ChannelAccess",
    "ChannelType",
    "ParsedRegister",
    "GUIBoundaryController",
    "LockStatus",
    "CscapeCompilerDispatcher",
    "CompilationResult",
    "CscapeOutputScraper",
    "DiagnosticSeverity",
    "OutputDiagnostic",
    "ScraperReport",
]
