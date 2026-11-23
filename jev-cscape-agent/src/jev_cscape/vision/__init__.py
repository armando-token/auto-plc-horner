"""Vision Grounding & UI Pane Analyzer for Horner Cscape 10.2.

Provides visual region segmentation, contrast and element visibility verification,
and fallback coordinate resolution for unexposed MFC controls.
"""

from .grounding import (
    DEFAULT_SCREENSHOT_PATH,
    SUPPORTED_RESOLUTIONS,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_LARGE_TEXT_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    FallbackCoordinate,
    VisionAnalysisReport,
    VisionGroundingEngine,
    WindowRegion,
    calculate_contrast_ratio,
    calculate_relative_luminance,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
)

__all__ = [
    "DEFAULT_SCREENSHOT_PATH",
    "SUPPORTED_RESOLUTIONS",
    "WCAG_AAA_BADGE_CONTRAST_TARGET",
    "WCAG_AAA_LARGE_TEXT_CONTRAST_TARGET",
    "WCAG_AAA_TEXT_CONTRAST_TARGET",
    "WCAG_GRAPHICAL_CONTRAST_TARGET",
    "FallbackCoordinate",
    "VisionAnalysisReport",
    "VisionGroundingEngine",
    "WindowRegion",
    "calculate_contrast_ratio",
    "calculate_relative_luminance",
    "srgb_channel_to_linear",
    "validate_wcag_aaa_contrast",
]
