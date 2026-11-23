"""Comprehensive pytest test suite for Cscape HMI Dynamic Horizon / Multi-Horizon Wavelet Decomposition SCADA Canvas (W195).

Work Package: W195 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY

Architectural Coverage:
1. Section 1: Pure ST POU AST parsing, symbol binding, and STParser validation (%R1560..%R1567, %M364..%M365).
2. Section 2: Anti-ladder security guard asserting LadderForbiddenError on contacts, coils, rungs, mnemonics.
3. Section 3: WaveletDecompositionConfig, HorizonChannelData, and HorizonWaveletMetrics initialization and validation.
4. Section 4: Horizon chart band folding mathematics (4 bands, positive vs negative offset clamping, 75% compression).
5. Section 5: Discrete wavelet transform (Haar & Daubechies D4 MRA filters, approximation low-pass + detail high-pass).
6. Section 6: Standalone W3C SVG 1.1 vector canvas generation, XML validity, and structural elements.
7. Section 7: WCAG 2.1 AAA color contrast compliance (> 7.0:1 text, > 18:1 telemetry badges, > 3.0:1 graphics).
8. Section 8: Dynamic real-time signal modulation and channel/level selection across 4 channels.
9. Section 9: Horner RegisterTable synchronization (%R1560..%R1567, %M364..%M365) using PrivilegeMode.SYSTEM.
10. Section 10: Process safety interlocks (0xD301 chatter anomaly trip, 0xD302 drift saturation, 0xD303 render fault).
11. Section 11: ILogicUnit discrete scan cycle execution (100+ scan steps, auto-trip, auto-recovery).
12. Section 12: Deterministic 9-stage verification runner returning status == 'success' and stages_passed == 9.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.horizon_wavelet_canvas import (
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    COLOR_CARD_BORDER,
    COLOR_DARK_THEME_BACKING,
    COLOR_DARK_THEME_BACKING_1E1E1E,
    COLOR_DARK_THEME_SURFACE,
    COLOR_DECOUPLED_BADGE,
    COLOR_FOCUS_BLUE,
    COLOR_GRID_LINE,
    COLOR_GRID_TICK,
    COLOR_NEG_BAND_1,
    COLOR_NEG_BAND_2,
    COLOR_NEG_BAND_3,
    COLOR_NEG_BAND_4,
    COLOR_NOMINAL_GREEN,
    COLOR_POS_BAND_1,
    COLOR_POS_BAND_2,
    COLOR_POS_BAND_3,
    COLOR_POS_BAND_4,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_TRIP_CRIMSON,
    COLOR_WARNING_AMBER,
    COLOR_WAVELET_APPROX,
    COLOR_WAVELET_D1_CHATTER,
    COLOR_WAVELET_D2,
    COLOR_WAVELET_D3,
    DARK_THEME_TEXT_CONTRAST_RATIO,
    DECOUPLED_BADGE_CONTRAST_RATIO,
    DEFAULT_SAMPLE_COUNT,
    DIAG_EVENT_BASELINE_DRIFT_SATURATION,
    DIAG_EVENT_DRIFT_SATURATION,
    DIAG_EVENT_HF_SINGULARITY_BREACH,
    DIAG_EVENT_OK,
    DIAG_EVENT_RENDER_FAULT,
    DIAG_EVENT_SINGULARITY_BREACH,
    DRIFT_SLOPE_ALARM_THRESHOLD,
    DiagnosticCode,
    GRAPHICAL_BOUNDARY_CONTRAST_RATIO,
    HORIZON_WAVELET_PURE_ST_POU,
    HorizonChannelData,
    HorizonWaveletCanvas,
    HorizonWaveletCanvasSync,
    HorizonWaveletEngine,
    HorizonWaveletHmiSync,
    HorizonWaveletMetrics,
    HorizonWaveletStatusBits,
    NEGATIVE_BAND_COLORS,
    NOMINAL_ACTIVE_CHANNEL_COUNT,
    NOMINAL_HIGH_FREQUENCY_NOISE_RMS,
    NOMINAL_HIGH_FREQUENCY_NOISE_RMS_SCALED,
    NOMINAL_HORIZON_BAND_MULTIPLIERS_SCALED,
    NOMINAL_HORIZON_COMPRESSION_RATIO_PCT,
    NOMINAL_LOW_FREQUENCY_DRIFT_SLOPE,
    NOMINAL_LOW_FREQUENCY_DRIFT_SLOPE_SCALED,
    NOMINAL_SIGNAL_TO_NOISE_RATIO_DB,
    NOMINAL_SIGNAL_TO_NOISE_RATIO_DB_SCALED,
    NOMINAL_WAVELET_DECOMPOSITION_LEVEL,
    PLOT_LEFT,
    PLOT_RIGHT,
    PLOT_WIDTH,
    POSITIVE_BAND_COLORS,
    ProcessChannelId,
    SINGULARITY_RMS_TRIP_THRESHOLD,
    WAVELET_ERR_BASELINE_DRIFT_SATURATION,
    WAVELET_ERR_CHATTER_BREACH,
    WAVELET_ERR_DRIFT_SATURATION,
    WAVELET_ERR_HF_SINGULARITY_BREACH,
    WAVELET_ERR_OK,
    WAVELET_ERR_RENDER_FAULT,
    WAVELET_ERR_SINGULARITY_BREACH,
    WaveletDecompositionConfig,
    WaveletFamily,
    WaveletMraResult,
    WaveletStatusBits,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    calculate_contrast_ratio,
    clip_horizon_band,
    compute_horizon_folded_bands,
    create_canonical_canvas,
    create_canonical_horizon_wavelet_canvas,
    create_canonical_process_channels,
    create_mock_scan_context,
    dwt_daubechies4_step,
    dwt_haar_step,
    generate_horizon_wavelet_canvas_svg,
    generate_horizon_wavelet_svg,
    hex_to_relative_luminance,
    idwt_daubechies4_step,
    idwt_haar_step,
    run_horizon_wavelet_canvas_verification,
    srgb_channel_to_linear,
    validate_wcag_aaa_contrast,
    verify_horizon_wavelet_canvas_pure_st,
    verify_horizon_wavelet_pure_st,
    wavelet_mra_decompose,
)


# ============================================================================
# Section 1: Pure ST POU AST Parsing, Symbol Binding & STParser Validation
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Section 1.1: Verify Pure ST POU parses correctly via STParser and functions as PROGRAM."""
    assert verify_horizon_wavelet_canvas_pure_st() is True
    assert verify_horizon_wavelet_pure_st() is True

    parser = STParser()
    ast = parser.parse_pou(HORIZON_WAVELET_PURE_ST_POU)
    assert ast is not None
    assert ast.name == "HorizonWaveletCanvasSync"
    assert ast.pou_type == POUType.PROGRAM


def test_pure_st_pou_bound_registers() -> None:
    """Section 1.2: Verify all 10 Horner registers (%R1560..%R1567, %M364..%M365) are bound in AST."""
    parser = STParser()
    ast = parser.parse_pou(HORIZON_WAVELET_PURE_ST_POU)
    assert ast is not None

    expected_registers = [
        "%R1560", "%R1561", "%R1562", "%R1563",
        "%R1564", "%R1565", "%R1566", "%R1567",
        "%M364", "%M365",
    ]
    for reg in expected_registers:
        assert reg in ast.bound_registers, f"Register {reg} must be bound in POU AST"


def test_pure_st_pou_syntax_validation() -> None:
    """Section 1.3: Validate code syntax passes with SUCCESS status."""
    res = STParser.validate_code(HORIZON_WAVELET_PURE_ST_POU)
    assert res.status == AgentStatus.SUCCESS


def test_pure_st_pou_keywords_and_structure() -> None:
    """Section 1.4: Verify mandatory keywords exist in the pure ST POU text."""
    assert "PROGRAM HorizonWaveletCanvasSync" in HORIZON_WAVELET_PURE_ST_POU
    assert "END_PROGRAM" in HORIZON_WAVELET_PURE_ST_POU
    assert "VAR" in HORIZON_WAVELET_PURE_ST_POU
    assert "END_VAR" in HORIZON_WAVELET_PURE_ST_POU
    assert "WaveletChatterAnomalyTrip" in HORIZON_WAVELET_PURE_ST_POU
    assert "HorizonCanvasActive" in HORIZON_WAVELET_PURE_ST_POU


# ============================================================================
# Section 2: Anti-Ladder Security Guard Interception
# ============================================================================

def test_anti_ladder_security_guard_valid_st() -> None:
    """Section 2.1: Verify pure ST content passes SecurityGuard without error."""
    SecurityGuard.assert_pure_st_content(HORIZON_WAVELET_PURE_ST_POU)


def test_anti_ladder_security_guard_rejects_contacts() -> None:
    """Section 2.2: Verify ladder contacts (---[ ]---) are rejected immediately."""
    bad_code = "PROGRAM Bad1 VAR X: BOOL; END_VAR ---[ ]--- END_PROGRAM"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_code)


def test_anti_ladder_security_guard_rejects_coils() -> None:
    """Section 2.3: Verify ladder coils (---( )---) are rejected immediately."""
    bad_code = "PROGRAM Bad2 VAR X: BOOL; END_VAR ---( )--- END_PROGRAM"
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_code)


def test_anti_ladder_security_guard_rejects_mnemonics() -> None:
    """Section 2.4: Verify ladder mnemonics (XIC, OTE) are rejected."""
    bad_snippets = [
        "PROGRAM Bad3 VAR X: BOOL; END_VAR XIC %M364; END_PROGRAM",
        "PROGRAM Bad4 VAR X: BOOL; END_VAR OTE %M365; END_PROGRAM",
    ]
    for snippet in bad_snippets:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


def test_anti_ladder_security_guard_rejects_rungs_and_networks() -> None:
    """Section 2.5: Verify rung and network delimiters are rejected."""
    bad_snippets = [
        "PROGRAM Bad5 VAR X: BOOL; END_VAR RUNG 1 Active := TRUE; END_PROGRAM",
        "PROGRAM Bad6 VAR X: BOOL; END_VAR NETWORK 1 END_PROGRAM",
    ]
    for snippet in bad_snippets:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(snippet)


# ============================================================================
# Section 3: WaveletDecompositionConfig & HorizonChannelData Validation
# ============================================================================

def test_wavelet_decomposition_config_defaults() -> None:
    """Section 3.1: Verify default configuration parameters."""
    cfg = WaveletDecompositionConfig()
    assert cfg.viewport_width == CANVAS_VIEWPORT_WIDTH == 1200
    assert cfg.viewport_height == CANVAS_VIEWPORT_HEIGHT == 750
    assert cfg.band_count == 4
    assert cfg.decomposition_level == 3
    assert cfg.wavelet_family == "db4"
    assert cfg.sample_count == DEFAULT_SAMPLE_COUNT == 64
    assert cfg.selected_channel_id == 0
    assert cfg.noise_rms_trip_threshold == SINGULARITY_RMS_TRIP_THRESHOLD == 8.0
    assert cfg.drift_slope_alarm_threshold == DRIFT_SLOPE_ALARM_THRESHOLD == 0.50


def test_wavelet_decomposition_config_custom() -> None:
    """Section 3.2: Verify custom configuration initialization."""
    cfg = WaveletDecompositionConfig(
        viewport_width=1600,
        viewport_height=900,
        band_count=2,
        decomposition_level=1,
        wavelet_family="haar",
        sample_count=32,
        selected_channel_id=2,
        noise_rms_trip_threshold=10.0,
        drift_slope_alarm_threshold=0.80,
    )
    assert cfg.viewport_width == 1600
    assert cfg.viewport_height == 900
    assert cfg.band_count == 2
    assert cfg.decomposition_level == 1
    assert cfg.wavelet_family == "haar"
    assert cfg.sample_count == 32
    assert cfg.selected_channel_id == 2
    assert cfg.noise_rms_trip_threshold == 10.0
    assert cfg.drift_slope_alarm_threshold == 0.80


def test_horizon_channel_data_initialization() -> None:
    """Section 3.3: Verify HorizonChannelData dataclass fields and collections."""
    ch = HorizonChannelData(
        channel_id=1,
        name="Test Channel",
        tag="TI-001",
        unit="°C",
        baseline=100.0,
        full_scale_span=20.0,
        current_value=105.4,
        raw_samples=[100.0, 102.0, 105.4],
        timestamps=[0.0, 1.0, 2.0],
    )
    assert ch.channel_id == 1
    assert ch.name == "Test Channel"
    assert ch.tag == "TI-001"
    assert ch.unit == "°C"
    assert ch.baseline == 100.0
    assert ch.full_scale_span == 20.0
    assert ch.current_value == 105.4
    assert len(ch.raw_samples) == 3
    assert len(ch.timestamps) == 3


def test_canonical_process_channels_count_and_tags() -> None:
    """Section 3.4: Verify create_canonical_process_channels returns 4 calibrated channels."""
    channels = create_canonical_process_channels()
    assert len(channels) == 4

    expected_tags = ["TI-101", "PI-202", "IT-303", "JT-404"]
    expected_names = [
        "Reactor Bed Temperature",
        "Off-Gas Pressure",
        "CIP Network Latency",
        "Power Demand Jitter",
    ]
    expected_baselines = [450.0, 3.50, 12.5, 0.85]
    expected_spans = [40.0, 1.00, 10.0, 0.50]

    for idx, ch in enumerate(channels):
        assert ch.channel_id == idx + 1
        assert ch.tag == expected_tags[idx]
        assert ch.name == expected_names[idx]
        assert ch.baseline == expected_baselines[idx]
        assert ch.full_scale_span == expected_spans[idx]
        assert len(ch.raw_samples) == 64
        assert len(ch.timestamps) == 64


def test_horizon_wavelet_metrics_defaults() -> None:
    """Section 3.5: Verify HorizonWaveletMetrics initial production nominals."""
    m = HorizonWaveletMetrics()
    assert m.active_channel_count == NOMINAL_ACTIVE_CHANNEL_COUNT == 4
    assert m.horizon_band_multipliers_scaled == NOMINAL_HORIZON_BAND_MULTIPLIERS_SCALED == 4
    assert m.wavelet_decomposition_level == NOMINAL_WAVELET_DECOMPOSITION_LEVEL == 3
    assert m.high_frequency_noise_rms == NOMINAL_HIGH_FREQUENCY_NOISE_RMS == 4.8
    assert m.high_frequency_noise_rms_scaled == NOMINAL_HIGH_FREQUENCY_NOISE_RMS_SCALED == 48
    assert m.low_frequency_drift_slope == NOMINAL_LOW_FREQUENCY_DRIFT_SLOPE == 0.12
    assert m.low_frequency_drift_slope_scaled == NOMINAL_LOW_FREQUENCY_DRIFT_SLOPE_SCALED == 12
    assert m.signal_to_noise_ratio_db == NOMINAL_SIGNAL_TO_NOISE_RATIO_DB == 28.4
    assert m.signal_to_noise_ratio_db_scaled == NOMINAL_SIGNAL_TO_NOISE_RATIO_DB_SCALED == 284
    assert m.horizon_compression_ratio_pct == NOMINAL_HORIZON_COMPRESSION_RATIO_PCT == 75
    assert m.diagnostic_status_code == 0
    assert m.horizon_canvas_active is True
    assert m.wavelet_chatter_anomaly_trip is False


def test_diagnostic_code_equality_and_hashing() -> None:
    """Section 3.6: Verify DiagnosticCode handles signed/unsigned 16-bit comparisons."""
    code_trip = DiagnosticCode(0xD301)
    assert code_trip == 0xD301
    assert code_trip == 54017
    assert code_trip == -11519
    assert hash(code_trip) == hash(int(code_trip))

    code_drift = DiagnosticCode(0xD302)
    assert code_drift == 0xD302
    assert code_drift == 54018
    assert code_drift == -11518

    code_render = DiagnosticCode(0xD303)
    assert code_render == 0xD303
    assert code_render == 54019
    assert code_render == -11517

    assert DIAG_EVENT_OK == 0
    assert WAVELET_ERR_OK == 0
    assert WAVELET_ERR_SINGULARITY_BREACH == 0xD301
    assert WAVELET_ERR_DRIFT_SATURATION == 0xD302
    assert WAVELET_ERR_RENDER_FAULT == 0xD303


# ============================================================================
# Section 4: Horizon Chart Band Folding Mathematics & Geometry
# ============================================================================

def test_clip_horizon_band_positive_zero_deviation() -> None:
    """Section 4.1: Verify baseline values yield zero height across all positive bands."""
    baseline = 100.0
    values = [100.0, 100.0, 100.0]
    for b in range(1, 5):
        h = clip_horizon_band(values, baseline, b, 10.0, True, 60.0)
        assert all(val == 0.0 for val in h)


def test_clip_horizon_band_positive_progressive_clamping() -> None:
    """Section 4.2: Verify positive excursion heights saturate per band span."""
    baseline = 100.0
    band_span = 10.0  # Band 1: 0..10, Band 2: 10..20, Band 3: 20..30, Band 4: 30..40
    track_h = 60.0

    # Value 105.0 -> dev = 5.0 (Band 1 half-full, Bands 2..4 empty)
    h_b1 = clip_horizon_band([105.0], baseline, 1, band_span, True, track_h)
    h_b2 = clip_horizon_band([105.0], baseline, 2, band_span, True, track_h)
    assert abs(h_b1[0] - 30.0) < 1e-4
    assert h_b2[0] == 0.0

    # Value 125.0 -> dev = 25.0 (Band 1 full 60, Band 2 full 60, Band 3 half 30, Band 4 empty 0)
    h1 = clip_horizon_band([125.0], baseline, 1, band_span, True, track_h)[0]
    h2 = clip_horizon_band([125.0], baseline, 2, band_span, True, track_h)[0]
    h3 = clip_horizon_band([125.0], baseline, 3, band_span, True, track_h)[0]
    h4 = clip_horizon_band([125.0], baseline, 4, band_span, True, track_h)[0]
    assert h1 == 60.0
    assert h2 == 60.0
    assert abs(h3 - 30.0) < 1e-4
    assert h4 == 0.0


def test_clip_horizon_band_negative_offset() -> None:
    """Section 4.3: Verify negative excursions invert and mirror upward."""
    baseline = 100.0
    band_span = 10.0
    track_h = 50.0

    # Value 95.0 -> negative dev = 5.0 (Band 1 half-full 25.0)
    h_neg1 = clip_horizon_band([95.0], baseline, 1, band_span, False, track_h)[0]
    assert abs(h_neg1 - 25.0) < 1e-4

    # Value 85.0 -> negative dev = 15.0 (Band 1 full 50.0, Band 2 half 25.0)
    h_neg1_full = clip_horizon_band([85.0], baseline, 1, band_span, False, track_h)[0]
    h_neg2_half = clip_horizon_band([85.0], baseline, 2, band_span, False, track_h)[0]
    assert h_neg1_full == 50.0
    assert abs(h_neg2_half - 25.0) < 1e-4


def test_clip_horizon_band_zero_span_handling() -> None:
    """Section 4.4: Zero or negative band span returns zeros without division by zero."""
    h = clip_horizon_band([105.0], 100.0, 1, 0.0, True, 50.0)
    assert all(val == 0.0 for val in h)


def test_compute_horizon_folded_bands_structure() -> None:
    """Section 4.5: Verify compute_horizon_folded_bands output schema and keys."""
    samples = [450.0, 460.0, 470.0, 440.0, 430.0]
    bands_res = compute_horizon_folded_bands(samples, baseline=450.0, full_scale_span=40.0, band_count=4)

    assert "x_coords" in bands_res
    assert "baseline_y" in bands_res
    assert "positive_bands" in bands_res
    assert "negative_bands" in bands_res
    assert "compression_ratio_pct" in bands_res
    assert len(bands_res["positive_bands"]) == 4
    assert len(bands_res["negative_bands"]) == 4
    assert bands_res["compression_ratio_pct"] == 75


def test_compute_horizon_folded_bands_svg_paths() -> None:
    """Section 4.6: Verify SVG paths are closed polygon paths (M ... L ... Z)."""
    samples = [450.0, 465.0, 475.0, 485.0, 450.0]
    bands_res = compute_horizon_folded_bands(samples, baseline=450.0, full_scale_span=40.0, band_count=4)

    pos_bands = bands_res["positive_bands"]
    # At least Band 1 should have valid path
    assert pos_bands[0]["svg_path"].startswith("M")
    assert pos_bands[0]["svg_path"].endswith("Z")
    assert pos_bands[0]["color"] == COLOR_POS_BAND_1


def test_compute_horizon_folded_bands_short_sample_fallback() -> None:
    """Section 4.7: Sample counts < 2 return empty paths safely."""
    res = compute_horizon_folded_bands([450.0], baseline=450.0, full_scale_span=40.0)
    assert res.get("positive_paths", res.get("positive_bands")) == []


# ============================================================================
# Section 5: Discrete Wavelet Transform (DWT) & Multi-Resolution Analysis
# ============================================================================

def test_dwt_haar_forward_and_inverse_single_step() -> None:
    """Section 5.1: Verify Haar single-level forward and inverse exact reconstruction."""
    sig = [2.0, 4.0, 6.0, 8.0, 10.0, 12.0]
    a, d = dwt_haar_step(sig)
    rec = idwt_haar_step(a, d)
    assert len(a) == 3
    assert len(d) == 3
    assert len(rec) == 6
    diff = max(abs(s - r) for s, r in zip(sig, rec))
    assert diff < 1e-12


def test_dwt_haar_odd_length_handling() -> None:
    """Section 5.2: Verify Haar step handles odd-length signals gracefully."""
    sig = [1.0, 3.0, 5.0]
    a, d = dwt_haar_step(sig)
    assert len(a) == 2
    assert len(d) == 2


def test_dwt_daubechies4_forward_and_inverse_single_step() -> None:
    """Section 5.3: Verify Daubechies D4 single-level forward and inverse exact reconstruction."""
    sig = [1.0, 2.5, 4.0, 3.5, 2.0, -1.0, 0.5, 3.0]
    a, d = dwt_daubechies4_step(sig)
    rec = idwt_daubechies4_step(a, d)
    assert len(a) == 4
    assert len(d) == 4
    assert len(rec) == 8
    diff = max(abs(s - r) for s, r in zip(sig, rec))
    assert diff < 1e-12, f"DB4 reconstruction error must be < 1e-12, got {diff}"


def test_dwt_daubechies4_invalid_length_validation() -> None:
    """Section 5.4: Verify DB4 raises ValueError for length < 4 or odd length."""
    with pytest.raises(ValueError):
        dwt_daubechies4_step([1.0, 2.0])
    with pytest.raises(ValueError):
        dwt_daubechies4_step([1.0, 2.0, 3.0, 4.0, 5.0])


def test_wavelet_mra_decompose_levels_1_2_3() -> None:
    """Section 5.5: Verify 1-, 2-, and 3-level MRA decompositions."""
    sig = [math.sin(i * 0.1) for i in range(64)]

    for lvl in (1, 2, 3):
        mra = wavelet_mra_decompose(sig, level=lvl, family="db4")
        assert len(mra.details) == lvl
        assert len(mra.reconstructed_details) == lvl
        assert len(mra.reconstructed_approximation) == 64
        assert isinstance(mra.high_frequency_noise_rms, float)
        assert isinstance(mra.low_frequency_drift_slope, float)
        assert isinstance(mra.snr_db, float)


def test_wavelet_mra_decompose_haar_and_db4() -> None:
    """Section 5.6: Verify both Haar and DB4 families decompose properly."""
    sig = [math.cos(i * 0.15) for i in range(32)]
    mra_db4 = wavelet_mra_decompose(sig, level=2, family="db4")
    mra_haar = wavelet_mra_decompose(sig, level=2, family="haar")

    assert len(mra_db4.details) == 2
    assert len(mra_haar.details) == 2
    assert len(mra_db4.reconstructed_approximation) == 32
    assert len(mra_haar.reconstructed_approximation) == 32


def test_wavelet_mra_noise_rms_and_drift_slope_calculation() -> None:
    """Section 5.7: Verify HF noise RMS and drift slope on calibrated signal."""
    channels = create_canonical_process_channels(sample_count=64)
    ch1 = channels[0]
    mra = wavelet_mra_decompose(ch1.raw_samples, level=3, family="db4")

    # Channel 1 was calibrated to 4.8 RMS chatter
    assert abs(mra.high_frequency_noise_rms - 4.8) < 0.2
    assert mra.snr_db > 3.0
    assert isinstance(mra.low_frequency_drift_slope, float)


# ============================================================================
# Section 6: Standalone W3C SVG 1.1 Vector Canvas Generation & XML Validity
# ============================================================================

def test_render_svg_xml_validity() -> None:
    """Section 6.1: Verify render_svg produces well-formed W3C SVG 1.1 XML."""
    canvas = create_canonical_horizon_wavelet_canvas()
    svg_str = canvas.render_svg()
    assert svg_str is not None
    assert len(svg_str) > 500

    # Parse with standard XML parser
    root = ET.fromstring(svg_str)
    assert root.tag.endswith("svg")
    assert root.attrib.get("version") == "1.1"
    assert root.attrib.get("width") == "1200"
    assert root.attrib.get("height") == "750"


def test_render_svg_structural_elements() -> None:
    """Section 6.2: Verify SVG contains headers, selectors, tracks, and HUD cards."""
    canvas = create_canonical_horizon_wavelet_canvas()
    svg_str = canvas.render_svg()

    assert 'id="canvas-header"' in svg_str
    assert 'id="header-badge"' in svg_str
    assert 'id="controls-toolbar"' in svg_str
    assert 'id="channel-selector"' in svg_str
    assert 'id="wavelet-level-toggle"' in svg_str
    assert 'id="horizon-tracks-container"' in svg_str
    assert 'id="telemetry-hud"' in svg_str
    assert 'id="hud-card-config"' in svg_str
    assert 'id="hud-card-noise"' in svg_str
    assert 'id="hud-card-drift"' in svg_str
    assert 'id="hud-card-compression"' in svg_str
    assert 'id="hud-card-status"' in svg_str
    assert 'id="hud-card-legend"' in svg_str
    assert 'id="status-bar"' in svg_str


def test_render_svg_with_selected_channel_filter() -> None:
    """Section 6.3: Verify selecting a single channel isolates that track."""
    canvas = create_canonical_horizon_wavelet_canvas()
    canvas.select_channel(2)
    svg_str = canvas.render_svg()

    # Track 2 present
    assert 'id="horizon-channel-track-2"' in svg_str
    # Track 1 and 3 not rendered
    assert 'id="horizon-channel-track-1"' not in svg_str
    assert 'id="horizon-channel-track-3"' not in svg_str


def test_render_svg_fault_state_markup() -> None:
    """Section 6.4: Verify 0xD303 render fault produces valid fallback SVG with warning."""
    canvas = create_canonical_horizon_wavelet_canvas()
    canvas.trigger_render_fault()
    svg_str = canvas.render_svg()

    assert "SVG Render Fault 0xD303" in svg_str
    root = ET.fromstring(svg_str)
    assert root.tag.endswith("svg")


def test_generate_horizon_wavelet_svg_alias() -> None:
    """Section 6.5: Verify alias generate_horizon_wavelet_svg matches canonical renderer."""
    canvas = create_canonical_horizon_wavelet_canvas()
    s1 = generate_horizon_wavelet_canvas_svg(canvas)
    s2 = generate_horizon_wavelet_svg(canvas)
    assert s1 == s2


# ============================================================================
# Section 7: WCAG 2.1 AAA Accessibility & Color Contrast Compliance
# ============================================================================

def test_srgb_channel_to_linear() -> None:
    """Section 7.1: Verify sRGB channel to linear conversion."""
    assert srgb_channel_to_linear(0.0) == 0.0
    assert abs(srgb_channel_to_linear(1.0) - 1.0) < 1e-4
    assert srgb_channel_to_linear(0.03928) == pytest.approx(0.03928 / 12.92, rel=1e-3)


def test_hex_to_relative_luminance_black_white() -> None:
    """Section 7.2: Verify relative luminance for black, white, and shorthand hex."""
    assert hex_to_relative_luminance("#000000") == 0.0
    assert abs(hex_to_relative_luminance("#FFFFFF") - 1.0) < 1e-4
    assert abs(hex_to_relative_luminance("#FFF") - 1.0) < 1e-4


def test_wcag_aaa_text_contrast() -> None:
    """Section 7.3: Verify primary text contrast on dark backing > 7.0:1 (WCAG AAA)."""
    contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
    assert contrast >= WCAG_AAA_TEXT_CONTRAST_TARGET
    assert contrast > 15.0  # Actually ~17.39:1


def test_wcag_aaa_badge_contrast() -> None:
    """Section 7.4: Verify decoupled badge contrast > 18.0:1 (WCAG AAA extreme)."""
    contrast = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
    assert contrast >= WCAG_AAA_BADGE_CONTRAST_TARGET
    assert contrast > 18.0  # Actually ~18.44:1


def test_wcag_aaa_graphical_contrast() -> None:
    """Section 7.5: Verify all SCADA positive/negative band colors meet graphical target (> 3.0:1)."""
    for color in POSITIVE_BAND_COLORS + NEGATIVE_BAND_COLORS:
        contrast = calculate_contrast_ratio(color, COLOR_DARK_THEME_BACKING)
        assert contrast >= WCAG_GRAPHICAL_CONTRAST_TARGET, (
            f"Color {color} must have contrast >= 3.0:1, got {contrast:.2f}:1"
        )


def test_validate_wcag_aaa_contrast_helper() -> None:
    """Section 7.6: Verify validate_wcag_aaa_contrast helper returns passing result."""
    all_ok, badge_c, theme_c, min_gfx = validate_wcag_aaa_contrast()
    assert all_ok is True
    assert badge_c >= 18.0
    assert theme_c >= 7.0
    assert min_gfx >= 3.0


# ============================================================================
# Section 8: Dynamic Real-Time Signal Modulation & Channel Selection
# ============================================================================

def test_canvas_select_channel() -> None:
    """Section 8.1: Verify select_channel bounds checking and configuration update."""
    canvas = create_canonical_horizon_wavelet_canvas()
    assert canvas.config.selected_channel_id == 0

    canvas.select_channel(3)
    assert canvas.config.selected_channel_id == 3

    # Out of bounds ignored
    canvas.select_channel(99)
    assert canvas.config.selected_channel_id == 3

    canvas.select_channel(0)
    assert canvas.config.selected_channel_id == 0


def test_canvas_set_decomposition_level() -> None:
    """Section 8.2: Verify set_decomposition_level configures and triggers re-evaluation."""
    canvas = create_canonical_horizon_wavelet_canvas()
    assert canvas.config.decomposition_level == 3

    canvas.set_decomposition_level(2)
    assert canvas.config.decomposition_level == 2
    assert canvas.metrics.wavelet_decomposition_level == 2
    assert canvas.reg_table.read_word("%R1562") == 2

    canvas.set_decomposition_level(1)
    assert canvas.config.decomposition_level == 1
    assert canvas.metrics.wavelet_decomposition_level == 1

    # Out of bounds ignored
    canvas.set_decomposition_level(5)
    assert canvas.config.decomposition_level == 1


def test_canvas_set_wavelet_family() -> None:
    """Section 8.3: Verify set_wavelet_family toggles between haar and db4."""
    canvas = create_canonical_horizon_wavelet_canvas()
    assert canvas.config.wavelet_family == "db4"

    canvas.set_wavelet_family("haar")
    assert canvas.config.wavelet_family == "haar"

    canvas.set_wavelet_family("db4")
    assert canvas.config.wavelet_family == "db4"


def test_canvas_custom_channel_data_modulation() -> None:
    """Section 8.4: Verify modifying channel data updates evaluation."""
    canvas = create_canonical_horizon_wavelet_canvas()
    # Modulate channel 1 raw samples
    new_samples = [460.0 + 5.0 * math.sin(i * 0.2) for i in range(64)]
    canvas.channels[0].raw_samples = new_samples
    canvas.channels[0].current_value = new_samples[-1]

    canvas.evaluate_wavelet_decomposition()
    assert canvas.channels[0].channel_id in canvas.mra_results
    assert canvas.channels[0].channel_id in canvas.folded_bands


# ============================================================================
# Section 9: Horner RegisterTable Memory Synchronization
# ============================================================================

def test_register_table_sync_nominal_words() -> None:
    """Section 9.1: Verify all 8 word registers (%R1560..%R1567) synchronized with SYSTEM privilege."""
    canvas = create_canonical_horizon_wavelet_canvas()
    reg = canvas.reg_table

    assert reg.read_word("%R1560") == NOMINAL_ACTIVE_CHANNEL_COUNT == 4
    assert reg.read_word("%R1561") == NOMINAL_HORIZON_BAND_MULTIPLIERS_SCALED == 4
    assert reg.read_word("%R1562") == NOMINAL_WAVELET_DECOMPOSITION_LEVEL == 3
    assert reg.read_word("%R1563") == NOMINAL_HIGH_FREQUENCY_NOISE_RMS_SCALED == 48
    assert reg.read_word("%R1564") == NOMINAL_LOW_FREQUENCY_DRIFT_SLOPE_SCALED == 12
    assert reg.read_word("%R1565") == NOMINAL_SIGNAL_TO_NOISE_RATIO_DB_SCALED == 284
    assert reg.read_word("%R1566") == NOMINAL_HORIZON_COMPRESSION_RATIO_PCT == 75
    assert reg.read_word("%R1567") == DIAG_EVENT_OK == 0


def test_register_table_sync_nominal_bits() -> None:
    """Section 9.2: Verify discrete coils (%M364..%M365) synchronized."""
    canvas = create_canonical_horizon_wavelet_canvas()
    reg = canvas.reg_table

    assert reg.read_bit("%M364") is True
    assert reg.read_bit("%M365") is False


def test_register_table_privilege_mode_system() -> None:
    """Section 9.3: Verify writes require or pass PrivilegeMode.SYSTEM properly."""
    reg = RegisterTable()
    # Direct write using PrivilegeMode.SYSTEM
    reg.write_word("%R1560", 4, privilege=PrivilegeMode.SYSTEM)
    assert reg.read_word("%R1560") == 4


# ============================================================================
# Section 10: Process Safety Interlocks & Diagnostic Anomaly Trips
# ============================================================================

def test_chatter_singularity_breach_trip_0xd301() -> None:
    """Section 10.1: Verify 0xD301 singularity breach sets %R1567, %M365, and status bits."""
    canvas = create_canonical_horizon_wavelet_canvas()
    canvas.trigger_singularity_breach(noise_rms=12.5)

    assert canvas.diagnostic_code == WAVELET_ERR_SINGULARITY_BREACH
    assert canvas.diagnostic_code == 0xD301
    assert canvas.metrics.wavelet_chatter_anomaly_trip is True
    assert canvas.reg_table.read_bit("%M365") is True
    assert DiagnosticCode(canvas.reg_table.read_word("%R1567")) == 0xD301
    assert (canvas.status_bits & HorizonWaveletStatusBits.CHATTER_ANOMALY_TRIP) != 0


def test_drift_saturation_trip_0xd302() -> None:
    """Section 10.2: Verify 0xD302 baseline drift saturation sets %R1567 and DRIFT_SATURATION_ALARM."""
    canvas = create_canonical_horizon_wavelet_canvas()
    canvas.trigger_drift_saturation(drift_slope=0.85)

    assert canvas.diagnostic_code == WAVELET_ERR_DRIFT_SATURATION
    assert canvas.diagnostic_code == 0xD302
    assert canvas.metrics.wavelet_chatter_anomaly_trip is False
    assert canvas.reg_table.read_bit("%M365") is False
    assert DiagnosticCode(canvas.reg_table.read_word("%R1567")) == 0xD302


def test_render_fault_trip_0xd303() -> None:
    """Section 10.3: Verify 0xD303 render fault sets %R1567 and preserves %M365=False."""
    canvas = create_canonical_horizon_wavelet_canvas()
    canvas.trigger_render_fault()

    assert canvas.diagnostic_code == WAVELET_ERR_RENDER_FAULT
    assert canvas.diagnostic_code == 0xD303
    assert DiagnosticCode(canvas.reg_table.read_word("%R1567")) == 0xD303


def test_nominal_reset_after_faults() -> None:
    """Section 10.4: Verify reset_nominal restores healthy operating state and cleared codes."""
    canvas = create_canonical_horizon_wavelet_canvas()
    canvas.trigger_singularity_breach()
    assert canvas.metrics.wavelet_chatter_anomaly_trip is True

    canvas.reset_nominal()
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.metrics.wavelet_chatter_anomaly_trip is False
    assert canvas.reg_table.read_bit("%M364") is True
    assert canvas.reg_table.read_bit("%M365") is False
    assert canvas.reg_table.read_word("%R1567") == 0


# ============================================================================
# Section 11: ILogicUnit Scan Cycle Execution (100+ Scan Steps)
# ============================================================================

def test_ilogic_unit_interface_compliance() -> None:
    """Section 11.1: Verify HorizonWaveletCanvas satisfies ILogicUnit abstract base class."""
    canvas = create_canonical_horizon_wavelet_canvas()
    assert isinstance(canvas, ILogicUnit)
    assert hasattr(canvas, "scan_step")
    assert hasattr(canvas, "execute")


def test_ilogic_unit_single_scan_step() -> None:
    """Section 11.2: Verify scan_step executes discrete scan logic and syncs registers."""
    canvas = create_canonical_horizon_wavelet_canvas()
    canvas.scan_step(dt=0.01)

    assert canvas.reg_table.read_word("%R1560") == 4
    assert canvas.reg_table.read_bit("%M364") is True


def test_ilogic_unit_100_scan_steps_continuous_soak() -> None:
    """Section 11.3: Verify continuous 100+ scan steps execute deterministically without state corruption."""
    canvas = create_canonical_horizon_wavelet_canvas()

    for cycle in range(1, 105):
        canvas.scan_step(dt=0.01)

    # State should remain fully nominal
    assert canvas.diagnostic_code == DIAG_EVENT_OK
    assert canvas.reg_table.read_word("%R1567") == 0
    assert canvas.reg_table.read_bit("%M364") is True
    assert canvas.reg_table.read_bit("%M365") is False


def test_ilogic_unit_auto_trip_on_register_noise_injection() -> None:
    """Section 11.4: Injecting noise >= 80 into %R1563 causes scan cycle to auto-trip %M365 and 0xD301."""
    canvas = create_canonical_horizon_wavelet_canvas()
    canvas.reg_table.write_word("%R1563", 95, privilege=PrivilegeMode.SYSTEM)

    ctx = create_mock_scan_context(reg_table=canvas.reg_table)
    canvas.execute(ctx)

    assert canvas.diagnostic_code == WAVELET_ERR_SINGULARITY_BREACH
    assert canvas.metrics.wavelet_chatter_anomaly_trip is True
    assert canvas.reg_table.read_bit("%M365") is True
    assert DiagnosticCode(canvas.reg_table.read_word("%R1567")) == 0xD301


def test_ilogic_unit_auto_trip_on_register_drift_injection() -> None:
    """Section 11.5: Injecting drift >= 50 into %R1564 causes scan cycle to auto-trip 0xD302."""
    canvas = create_canonical_horizon_wavelet_canvas()
    canvas.reg_table.write_word("%R1564", 75, privilege=PrivilegeMode.SYSTEM)

    ctx = create_mock_scan_context(reg_table=canvas.reg_table)
    canvas.execute(ctx)

    assert canvas.diagnostic_code == WAVELET_ERR_DRIFT_SATURATION
    assert DiagnosticCode(canvas.reg_table.read_word("%R1567")) == 0xD302


# ============================================================================
# Section 12: Deterministic 9-Stage Verification Suite Runner
# ============================================================================

def test_verification_runner_success() -> None:
    """Section 12.1: Verify run_horizon_wavelet_canvas_verification returns status == 'success'."""
    evidence = run_horizon_wavelet_canvas_verification()
    assert evidence["status"] == "success"
    assert evidence["error_code"] is None


def test_verification_runner_all_9_stages_pass() -> None:
    """Section 12.2: Verify all 9 verification stages pass deterministically."""
    evidence = run_horizon_wavelet_canvas_verification()
    data = evidence["data"]
    assert data["checks_passed"] == 9
    assert data["total_checks"] == 9
    assert len(data["tests"]) == 9
    for stage_test in data["tests"]:
        assert stage_test["passed"] is True, f"Stage {stage_test['stage']} must pass: {stage_test['details']}"


def test_verification_runner_file_exports(tmp_path: Path) -> None:
    """Section 12.3: Verify runner exports valid JSON evidence and sample SVG when paths provided."""
    ev_path = tmp_path / "horizon_wavelet_canvas_evidence.json"
    svg_path = tmp_path / "horizon_wavelet_canvas_sample.svg"

    evidence = run_horizon_wavelet_canvas_verification(
        output_path=str(ev_path),
        sample_svg_path=str(svg_path),
    )

    assert evidence["status"] == "success"
    assert ev_path.exists()
    assert svg_path.exists()

    # Validate written files
    with open(ev_path, "r", encoding="utf-8") as f:
        loaded_ev = json.load(f)
    assert loaded_ev["status"] == "success"

    with open(svg_path, "r", encoding="utf-8") as f:
        svg_content = f.read()
    ET.fromstring(svg_content)  # Must be valid XML


def test_canvas_aliases_and_factory() -> None:
    """Section 12.4: Verify class aliases and factory helpers."""
    assert HorizonWaveletCanvasSync is HorizonWaveletCanvas
    assert HorizonWaveletHmiSync is HorizonWaveletCanvas
    assert HorizonWaveletEngine is HorizonWaveletCanvas

    c1 = create_canonical_horizon_wavelet_canvas()
    c2 = create_canonical_canvas()
    assert isinstance(c1, HorizonWaveletCanvas)
    assert isinstance(c2, HorizonWaveletCanvas)
