"""Unit Tests for Cscape HMI Dynamic Chernoff Face Process Anomaly Avatar (W096).

Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI.
"""

from __future__ import annotations

import math
from pathlib import Path
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.contracts import AgentStatus
from jev_cscape.hmi.chernoff_avatar import (
    AvatarSeverity,
    ChernoffAvatarGenerator,
    ChernoffGeometry,
    ChernoffStatusBits,
    CHERNOFF_AVATAR_PURE_ST_POU,
    calculate_contrast_ratio,
    calculate_relative_luminance,
    evaluate_avatar_color,
    interpolate_rgb,
    perlin_smootherstep,
    run_chernoff_avatar_verification,
)
from jev_cscape.iec.st_parser import STParser, POUType
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


class TestChernoffAvatar:
    """Test suite for W096 Chernoff Avatar Engine."""

    def test_pure_st_pou_ast_parsing(self) -> None:
        """Verify Pure ST POU validation and AST symbol bindings."""
        SecurityGuard.assert_pure_st_content(CHERNOFF_AVATAR_PURE_ST_POU)
        res = STParser.validate_code(CHERNOFF_AVATAR_PURE_ST_POU)
        assert res.status == AgentStatus.SUCCESS

        ast = STParser.parse_pou(CHERNOFF_AVATAR_PURE_ST_POU)
        assert ast.name == "ChernoffAvatarRasterizerSync"
        assert ast.pou_type == POUType.PROGRAM
        assert "%R570" in ast.bound_registers
        assert "%R577" in ast.bound_registers
        assert "%M133" in ast.bound_registers
        assert "%M134" in ast.bound_registers

    def test_ladder_construct_interception(self) -> None:
        """Verify ladder contacts and coils are intercepted fail-closed."""
        bad_st = """
        PROGRAM BadAvatarLadder
        VAR AnomalyBit : BOOL; END_VAR
        ---[ ]---( )---
        END_PROGRAM
        """
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(bad_st)

    def test_perlin_smootherstep_properties(self) -> None:
        """Verify 5th-order Perlin smootherstep boundary values and strict monotonicity."""
        assert abs(perlin_smootherstep(0.0)) < 1e-7
        assert abs(perlin_smootherstep(1.0) - 1.0) < 1e-7

        # Monotonicity
        prev = -1.0
        for i in range(101):
            val = perlin_smootherstep(i / 100.0)
            assert val >= prev
            prev = val

        # Zero derivative at boundaries (flat slopes)
        eps = 1e-4
        slope_start = (perlin_smootherstep(eps) - perlin_smootherstep(0.0)) / eps
        slope_end = (perlin_smootherstep(1.0) - perlin_smootherstep(1.0 - eps)) / eps
        assert abs(slope_start) < 1e-2
        assert abs(slope_end) < 1e-2

    def test_color_gradient_interpolation(self) -> None:
        """Verify smooth color interpolation from Healthy Cyan to Warning Amber to Critical Crimson."""
        color_nominal, glow_nom, sev_nom = evaluate_avatar_color(0.0)
        assert color_nominal == "#38BDF8"
        assert sev_nom == AvatarSeverity.NORMAL

        color_warn, glow_warn, sev_warn = evaluate_avatar_color(0.50)
        assert sev_warn == AvatarSeverity.WARNING

        color_crit, glow_crit, sev_crit = evaluate_avatar_color(0.95)
        assert sev_crit == AvatarSeverity.CRITICAL
        # Crimson color should have high red component
        assert color_crit.startswith("#")

    def test_wcag_aaa_contrast_ratio(self) -> None:
        """Verify dark backing badge (#0B0F19) provides > 18:1 contrast against white."""
        dark_badge_rgb = (11, 15, 25)
        white_rgb = (255, 255, 255)
        cr = calculate_contrast_ratio(white_rgb, dark_badge_rgb)
        assert cr >= 18.0

        # Cyan on dark badge
        cyan_rgb = (56, 189, 248)
        cr_cyan = calculate_contrast_ratio(cyan_rgb, dark_badge_rgb)
        assert cr_cyan >= 7.0  # AAA level for graphical/large text

    def test_mouth_camber_cubic_bezier(self) -> None:
        """Verify cubic Bézier mouth camber orientation for smile vs frown."""
        avatar = ChernoffAvatarGenerator()
        nom = [d.nominal_val for d in avatar.dimensions]

        # Smile (high stability)
        nom_smile = list(nom)
        nom_smile[6] = 95.0
        geom_smile = avatar.generate_geometry(nom_smile)
        assert geom_smile.mouth_camber > 0.0
        assert geom_smile.mouth_cp1y > geom_smile.mouth_y0

        # Frown (low stability)
        nom_frown = list(nom)
        nom_frown[6] = -90.0
        geom_frown = avatar.generate_geometry(nom_frown)
        assert geom_frown.mouth_camber < 0.0
        assert geom_frown.mouth_cp1y < geom_frown.mouth_y0

    def test_eyebrow_affine_rotation(self) -> None:
        """Verify eyebrow angle rotation creates valid SVG quadratic Bézier paths."""
        avatar = ChernoffAvatarGenerator()
        nom = [d.nominal_val for d in avatar.dimensions]

        geom = avatar.generate_geometry(nom)
        assert geom.left_eyebrow_path.startswith("M ")
        assert " Q " in geom.left_eyebrow_path
        assert geom.right_eyebrow_path.startswith("M ")
        assert " Q " in geom.right_eyebrow_path

    def test_sclera_pupil_clamping(self) -> None:
        """Verify pupil gaze deflection is strictly clamped within sclera bounding ellipse."""
        avatar = ChernoffAvatarGenerator()
        nom = [d.nominal_val for d in avatar.dimensions]

        # Far right excursion
        nom[7] = 50.0
        geom = avatar.generate_geometry(nom)
        max_limit = geom.eye_rx - geom.pupil_r - 2.0
        assert geom.pupil_offset_x <= max_limit
        assert geom.left_pupil_cx == geom.left_eye_cx + geom.pupil_offset_x

        # Far left excursion
        nom[7] = -50.0
        geom_left = avatar.generate_geometry(nom)
        assert geom_left.pupil_offset_x >= -max_limit

    def test_horner_ocs_register_synchronization(self) -> None:
        """Verify register synchronization across analog %R570..%R577 and coils %M133..%M134."""
        reg_table = RegisterTable()
        avatar = ChernoffAvatarGenerator(register_table=reg_table)
        nom = [d.nominal_val for d in avatar.dimensions]

        # Normal condition
        geom = avatar.generate_geometry(nom)
        avatar.sync_registers(nom, geom.anomaly_score, geom)

        assert reg_table.read_word("%R570") == 0
        assert reg_table.read_bit("%M133") is False
        assert reg_table.read_bit("%M134") is False

        # Critical condition
        crit_vals = [d.max_val for d in avatar.dimensions]
        geom_crit = avatar.generate_geometry(crit_vals)
        avatar.sync_registers(crit_vals, geom_crit.anomaly_score, geom_crit)

        assert reg_table.read_word("%R570") >= 700
        assert reg_table.read_bit("%M133") is True
        assert reg_table.read_bit("%M134") is True

    def test_svg_rendering_and_xml_structure(self) -> None:
        """Verify rendered SVG is well-formed XML and contains required elements."""
        avatar = ChernoffAvatarGenerator()
        svg_str = avatar.render_svg()

        # Parse XML
        root = ET.fromstring(svg_str)
        assert root.tag.endswith("svg")
        assert root.attrib.get("viewBox") == "0 0 1200 750"

        # Check required visual components
        assert "<defs>" in svg_str
        assert "glow-alarm" in svg_str
        assert "<ellipse" in svg_str
        assert "<circle" in svg_str
        assert "<path" in svg_str
        assert "%R570..%R577" in svg_str

    def test_end_to_end_verification_runner(self, tmp_path) -> None:
        """Verify 9-stage verification runner executes with 9/9 pass."""
        ev_file = tmp_path / "chernoff_evidence.json"
        svg_file = tmp_path / "chernoff_sample.svg"

        res = run_chernoff_avatar_verification(
            evidence_path=str(ev_file),
            svg_path=str(svg_file),
        )

        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert ev_file.exists()
        assert svg_file.exists()
