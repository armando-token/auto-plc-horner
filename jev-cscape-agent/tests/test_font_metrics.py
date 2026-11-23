"""Unit tests for Cscape HMI Vector Font Metrics, Text Wrapping & Multi-Lingual Dictionary (W066).

Tests:
1. Character width and string pixel length calculation across all 5 font presets (6x8, 8x16, 12x24, 16x32, 24x48).
2. CJK double-width glyph pixel width calculation.
3. Single-line text alignment offset calculation (Left, Center, Right; Top, Middle, Bottom).
4. Text wrapping algorithm breaking long strings cleanly at word boundaries.
5. Ellipsis truncation when text exceeds box dimensions without wrapping.
6. Multi-line bounding box height and line count evaluation.
7. Multi-lingual dictionary lookup in all 5 languages (EN, ES, DE, FR, ZH).
8. Missing key graceful fallback to tag key.
9. German and Spanish text expansion detection and overflow reporting.
10. WCAG 2.1 AA (4.5:1) and AAA (7.0:1) contrast ratio validation.
11. Horner OCS register synchronization (%R280..%R284, %M63..%M64).
12. Runtime language switching via %R280 and %M64 handshake coil.
13. Pure ST boundary enforcement: rejection of illegal ladder logic constructs.
14. Complete end-to-end verification runner and artifact JSON validation.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from jev_cscape.hmi.font_metrics import (
    FONT_PRESETS,
    TRANSLATION_CATALOG,
    FontEngineStatusFlag,
    FontMetricsLogicUnit,
    FontPresetId,
    HAlign,
    HmiLanguage,
    VAlign,
    check_wcag_contrast,
    compute_contrast_ratio,
    compute_string_pixel_width,
    layout_text_in_box,
    relative_luminance,
    truncate_with_ellipsis,
    verify_font_metrics_and_export_evidence,
    wrap_text_to_lines,
)
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


def test_font_presets_dimensions() -> None:
    """Verify character dimensions and line heights across all 5 standard presets."""
    expected = {
        FontPresetId.FONT_6x8: (6, 8),
        FontPresetId.FONT_8x16: (8, 16),
        FontPresetId.FONT_12x24: (12, 24),
        FontPresetId.FONT_16x32: (16, 32),
        FontPresetId.FONT_24x48: (24, 48),
    }
    for pid, (exp_w, exp_h) in expected.items():
        p = FONT_PRESETS[pid]
        assert p.char_width == exp_w
        assert p.char_height == exp_h
        assert p.baseline_offset > 0
        assert p.total_line_height >= exp_h


def test_cjk_double_width_metrics() -> None:
    """Verify CJK ideographs occupy double width compared to ASCII glyphs."""
    p = FONT_PRESETS[FontPresetId.FONT_8x16]
    ascii_sample = "ABC"
    cjk_sample = "配方管"  # 3 CJK chars

    w_ascii = compute_string_pixel_width(ascii_sample, p)
    w_cjk = compute_string_pixel_width(cjk_sample, p)

    assert w_ascii == 3 * 8
    assert w_cjk == 3 * (8 * 2)
    assert w_cjk == w_ascii * 2


def test_alignment_offsets_and_svg_generation() -> None:
    """Verify text alignment coordinates and generated SVG elements."""
    p = FONT_PRESETS[FontPresetId.FONT_8x16]
    box_x = 20
    box_y = 30
    box_w = 200
    box_h = 50

    # Left alignment
    res_l = layout_text_in_box("STATUS", box_x, box_y, box_w, box_h, p, h_align=HAlign.LEFT, v_align=VAlign.TOP)
    assert res_l.text_x == box_x
    assert res_l.text_y == box_y + p.baseline_offset
    assert 'text-anchor="start"' in res_l.svg_elements[0]

    # Center alignment
    res_c = layout_text_in_box("STATUS", box_x, box_y, box_w, box_h, p, h_align=HAlign.CENTER, v_align=VAlign.MIDDLE)
    assert res_c.text_x == box_x + box_w // 2
    assert 'text-anchor="middle"' in res_c.svg_elements[0]

    # Right alignment
    res_r = layout_text_in_box("STATUS", box_x, box_y, box_w, box_h, p, h_align=HAlign.RIGHT, v_align=VAlign.BOTTOM)
    assert res_r.text_x == box_x + box_w
    assert 'text-anchor="end"' in res_r.svg_elements[0]


def test_word_wrapping_clean_boundaries() -> None:
    """Verify text wrapping splits cleanly at word boundaries."""
    p = FONT_PRESETS[FontPresetId.FONT_8x16]
    text = "PRIMARY REACTOR PRESSURE RELIEF"
    # Max width 100 px allows 12 characters (8 px each)
    lines = wrap_text_to_lines(text, max_width_px=100, font=p)
    assert len(lines) >= 3
    for line in lines:
        assert compute_string_pixel_width(line, p) <= 100
        # No mid-word hyphens or dangling spaces
        assert not line.startswith(" ")
        assert not line.endswith(" ")


def test_ellipsis_truncation() -> None:
    """Verify text truncation with ellipsis when bounds are exceeded."""
    p = FONT_PRESETS[FontPresetId.FONT_8x16]
    long_label = "AUTOMATED_CIP_CLEANING_CYCLE_ACTIVE"
    # Box 100px holds max 12 chars
    res, was_clipped = truncate_with_ellipsis(long_label, max_width_px=100, font=p)
    assert was_clipped is True
    assert res.endswith("...")
    assert compute_string_pixel_width(res, p) <= 100

    # Short label should not truncate
    short_res, short_clipped = truncate_with_ellipsis("RUN", max_width_px=100, font=p)
    assert short_clipped is False
    assert short_res == "RUN"


def test_multiline_box_height_evaluation() -> None:
    """Verify vertical bounding box height and line clamping."""
    p = FONT_PRESETS[FontPresetId.FONT_8x16]
    text = "LINE ONE LINE TWO LINE THREE LINE FOUR"
    # Box width 80px, height 30px (line height is 18px, so max 1 line fits)
    res = layout_text_in_box(text, 0, 0, 80, 30, p, allow_wrap=True)
    assert res.is_clipped is True
    assert len(res.lines) <= 2


def test_multilingual_catalog_coverage() -> None:
    """Verify translation availability in all 5 languages."""
    unit = FontMetricsLogicUnit()
    required_tags = ["NAV_DASHBOARD", "NAV_ALARMS", "NAV_RECIPES", "BTN_START", "BTN_STOP", "ALM_CRITICAL_HIGH"]

    for tag in required_tags:
        for lang in HmiLanguage:
            txt, is_fallback = unit.get_text(tag, lang)
            assert not is_fallback
            assert len(txt) > 0


def test_missing_key_fallback() -> None:
    """Verify non-existent keys fall back to tag name and set fallback indicator."""
    unit = FontMetricsLogicUnit()
    txt, is_fallback = unit.get_text("UNREGISTERED_TAG_123", HmiLanguage.FRENCH)
    assert is_fallback is True
    assert txt == "UNREGISTERED_TAG_123"


def test_text_expansion_overflow_detection() -> None:
    """Verify German and Spanish expansion triggers overflow clipping."""
    p = FONT_PRESETS[FontPresetId.FONT_8x16]
    # Button is 110 px wide
    en_text = TRANSLATION_CATALOG["BTN_START"][HmiLanguage.ENGLISH]  # "Start" = 40 px
    de_text = TRANSLATION_CATALOG["BTN_START"][HmiLanguage.GERMAN]   # "Prozess Starten" = 120 px

    res_en = layout_text_in_box(en_text, 0, 0, 110, 25, p, allow_wrap=False)
    assert res_en.is_clipped is False

    res_de = layout_text_in_box(de_text, 0, 0, 110, 25, p, allow_wrap=False)
    assert res_de.is_clipped is True


def test_wcag_contrast_calculations() -> None:
    """Verify relative luminance and WCAG 2.1 contrast ratios."""
    # Black on White (#000000 on #FFFFFF) = 21:1
    ratio_max = compute_contrast_ratio("#000000", "#FFFFFF")
    assert abs(ratio_max - 21.0) < 0.1

    # Same color (#555555 on #555555) = 1.0:1
    ratio_same = compute_contrast_ratio("#555555", "#555555")
    assert abs(ratio_same - 1.0) < 0.05

    # Industrial Horner Green (#00FF00 on #000000)
    pass_aa, pass_aaa, ratio_green = check_wcag_contrast("#00FF00", "#000000")
    assert pass_aa is True
    assert ratio_green > 10.0


def test_horner_register_sync() -> None:
    """Verify %R280..%R284 and %M63..%M64 synchronization during scan cycles."""
    regs = RegisterTable()
    unit = FontMetricsLogicUnit(register_table=regs)

    ctx = ScanContext(
        cycle=1,
        dt_ms=10.0,
        elapsed_time_ms=10.0,
        get_register=lambda addr: regs.read_register(addr),
        set_register=lambda addr, val: regs.write_register(addr, val, privilege=PrivilegeMode.SYSTEM),
        get_variable=lambda name, default=None: default,
        set_variable=lambda name, val: None,
        record_fault=lambda fault: None,
    )

    # Pre-select Spanish (%R280 = 1)
    regs.write_word("%R280", 1, privilege=PrivilegeMode.SYSTEM)
    unit.execute(ctx)

    assert regs.read_word("%R280") == 1
    assert regs.read_word("%R281") & FontEngineStatusFlag.ACTIVE
    assert regs.read_word("%R282") > 0  # Rendered strings
    assert regs.read_word("%R284") == int(FontPresetId.FONT_8x16)


def test_runtime_language_switch_handshake() -> None:
    """Verify dynamic language switching via %R280 and %M64 handshake coil."""
    regs = RegisterTable()
    unit = FontMetricsLogicUnit(register_table=regs)

    # Initial scan (English)
    unit.solve(regs)
    assert unit.language == HmiLanguage.ENGLISH

    # Switch to Chinese (4) via %R280 and set %M64 handshake
    regs.write_word("%R280", 4, privilege=PrivilegeMode.SYSTEM)
    regs.write_bit("%M64", True, privilege=PrivilegeMode.SYSTEM)
    unit.solve(regs)

    assert unit.language == HmiLanguage.CHINESE
    assert regs.read_bit("%M64") is False  # Handshake self-cleared
    assert regs.read_word("%R281") & FontEngineStatusFlag.LANG_CHANGED


def test_pure_st_boundary_enforcement() -> None:
    """Verify IEC 61131-3 Pure ST boundary rejects ladder constructs."""
    valid_st = (
        "PROGRAM HmiLocalization\n"
        "VAR\n"
        "    LangIndex : INT;\n"
        "    FontPreset : INT;\n"
        "END_VAR\n"
        "LangIndex := %R280;\n"
        "FontPreset := %R284;\n"
        "END_PROGRAM"
    )
    SecurityGuard.assert_pure_st_content(valid_st)

    ladder_samples = [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(S)---",
        "---(R)---",
        "RUNG 1",
        "END_RUNG",
        "NETWORK 12",
        "XIC SelectLang",
        "OTE ApplyFont",
    ]
    for sample in ladder_samples:
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(f"{valid_st}\n{sample}")


def test_verification_runner_and_artifact(tmp_path: Path) -> None:
    """Verify end-to-end canonical verification runner and evidence generation."""
    evidence_file = tmp_path / "font_metrics_evidence.json"
    result = verify_font_metrics_and_export_evidence(output_evidence_path=str(evidence_file))

    assert result["status"] == "success"
    assert result["error_code"] is None
    assert result["data"]["tests_run"] == result["data"]["tests_passed"]
    assert evidence_file.exists()

    with open(evidence_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] == "success"
    assert "supported_languages" in data["data"]
