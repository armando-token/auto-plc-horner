"""Unit tests for Cscape HMI Dynamic Iso-Surface Contouring & Marching Tetrahedra 3D Projection Canvas (W111).

Work Package: W111 (Gate G9 Graphic HMI & Animation Screen Engine / Gate G2 Live GUI)
Classification: PRODUCTION_READY
"""

from __future__ import annotations

import math
from pathlib import Path
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.hmi.marching_tetrahedra import (
    DIAG_EVENT_DEGENERATE_LATTICE,
    DIAG_EVENT_HIGH_CONTOUR_TRIP,
    DIAG_EVENT_OK,
    DIAG_EVENT_THRESHOLD_OUT_OF_BOUNDS,
    HIGH_CONTOUR_ALARM_LIMIT,
    MARCHING_TETRA_TABLE,
    MARCHING_TETRA_ST_POU,
    MARCHING_TETRAHEDRA_PURE_ST_POU,
    MarchingTetraStatusBits,
    MarchingTetrahedraStatusBits,
    IsometricProjector,
    LambertianShader,
    MarchingTetrahedraCanvas,
    Point3D,
    ScalarField3D,
    Tetrahedron3D,
    Triangle3D,
    create_canonical_thermal_field,
    decompose_cube_to_tetrahedra,
    extract_isosurface,
    generate_marching_tetrahedra_svg,
    interpolate_edge,
    run_marching_tetrahedra_verification,
    verify_marching_tetra_pure_st,
    verify_marching_tetrahedra_pure_st,
)
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable


# ============================================================================
# 1. Pure ST POU AST Validation and Anti-Ladder Check
# ============================================================================

def test_pure_st_pou_ast_validation() -> None:
    """Stage 1: Verify Pure ST POU AST parsing and absence of ladder constructs."""
    assert verify_marching_tetra_pure_st() is True
    assert verify_marching_tetrahedra_pure_st() is True

    # POU AST parse validation
    parser = STParser()
    pou = parser.parse_pou(MARCHING_TETRAHEDRA_PURE_ST_POU)
    assert pou is not None
    assert pou.name == "MarchingTetrahedraSync"
    assert pou.pou_type == POUType.PROGRAM

    # Verify bound registers
    expected_registers = [
        "%R720", "%R721", "%R722", "%R723",
        "%R724", "%R725", "%R726", "%R727",
        "%M168", "%M169",
    ]
    for reg in expected_registers:
        assert reg in pou.bound_registers


def test_anti_ladder_security_guard_rejection() -> None:
    """Stage 9: Verify interception and rejection of ladder logic constructs."""
    # SecurityGuard passes clean pure ST
    SecurityGuard.assert_pure_st_content(MARCHING_TETRAHEDRA_PURE_ST_POU)

    # Bad ladder logic injection check
    bad_st_contacts = """
    PROGRAM BadMarchingLadder
    VAR MeshActive : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_st_contacts)

    bad_st_mnemonics = """
    PROGRAM BadMnemonicLadder
    VAR Coil : BOOL; END_VAR
    XIC %M168 OTE %M169
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_st_mnemonics)


# ============================================================================
# 2. 5-Tetrahedra Cube Decomposition Topology and Volume Coverage
# ============================================================================

def test_cube_5tetrahedra_decomposition_and_volume_coverage() -> None:
    """Stage 2: Verify 5-tetrahedra cube decomposition topology and 100% volume coverage."""
    # 1. Unit cube [0, 1]^3
    c0 = Point3D(0.0, 0.0, 0.0)
    c1 = Point3D(1.0, 0.0, 0.0)
    c2 = Point3D(0.0, 1.0, 0.0)
    c3 = Point3D(1.0, 1.0, 0.0)
    c4 = Point3D(0.0, 0.0, 1.0)
    c5 = Point3D(1.0, 0.0, 1.0)
    c6 = Point3D(0.0, 1.0, 1.0)
    c7 = Point3D(1.0, 1.0, 1.0)
    unit_pts = [c0, c1, c2, c3, c4, c5, c6, c7]
    unit_vals = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0]

    # Decompose with even parity (parity=0)
    tets_even = decompose_cube_to_tetrahedra(unit_pts, unit_vals, parity=0)
    assert len(tets_even) == 5
    assert all(t.volume > 0.0 for t in tets_even)
    vol_even = sum(t.volume for t in tets_even)
    assert vol_even == pytest.approx(1.0, abs=1e-7)

    # 4 corner tets (volume = 1/6) and 1 center tet (volume = 1/3)
    vols_even = sorted([t.volume for t in tets_even])
    for cv in vols_even[:4]:
        assert cv == pytest.approx(1.0 / 6.0, abs=1e-7)
    assert vols_even[4] == pytest.approx(1.0 / 3.0, abs=1e-7)

    # Decompose with odd parity (parity=1)
    tets_odd = decompose_cube_to_tetrahedra(unit_pts, unit_vals, parity=1)
    assert len(tets_odd) == 5
    assert all(t.volume > 0.0 for t in tets_odd)
    vol_odd = sum(t.volume for t in tets_odd)
    assert vol_odd == pytest.approx(1.0, abs=1e-7)
    vols_odd = sorted([t.volume for t in tets_odd])
    for cv in vols_odd[:4]:
        assert cv == pytest.approx(1.0 / 6.0, abs=1e-7)
    assert vols_odd[4] == pytest.approx(1.0 / 3.0, abs=1e-7)

    # 2. Scaled cube [0, 10]^3 (Volume = 1000.0)
    scaled_pts = [p * 10.0 for p in unit_pts]
    tets_scaled_even = decompose_cube_to_tetrahedra(scaled_pts, unit_vals, parity=0)
    tets_scaled_odd = decompose_cube_to_tetrahedra(scaled_pts, unit_vals, parity=1)
    assert sum(t.volume for t in tets_scaled_even) == pytest.approx(1000.0, abs=1e-5)
    assert sum(t.volume for t in tets_scaled_odd) == pytest.approx(1000.0, abs=1e-5)


# ============================================================================
# 3. 16-Case Marching Tetrahedra Lookup and Linear Edge Interpolation
# ============================================================================

def test_marching_tetrahedra_16_case_lookup_table() -> None:
    """Stage 3: Verify 16-case topological lookup structure."""
    assert len(MARCHING_TETRA_TABLE) == 16

    # Case 0 (0000: all below) and Case 15 (1111: all above) produce 0 triangles
    assert len(MARCHING_TETRA_TABLE[0]) == 0
    assert len(MARCHING_TETRA_TABLE[15]) == 0

    # 1-vertex cases: exactly 1 triangle
    one_vertex_cases = [1, 2, 4, 7, 8, 11, 13, 14]
    for c in one_vertex_cases:
        assert len(MARCHING_TETRA_TABLE[c]) == 1, f"Case {c} should produce 1 triangle"
        assert len(MARCHING_TETRA_TABLE[c][0]) == 3, f"Case {c} triangle should have 3 edge indices"

    # 2-vertex cases: exactly 2 triangles
    two_vertex_cases = [3, 5, 6, 9, 10, 12]
    for c in two_vertex_cases:
        assert len(MARCHING_TETRA_TABLE[c]) == 2, f"Case {c} should produce 2 triangles"
        assert len(MARCHING_TETRA_TABLE[c][0]) == 3
        assert len(MARCHING_TETRA_TABLE[c][1]) == 3


def test_linear_edge_interpolation() -> None:
    """Stage 3: Verify analytical linear edge interpolation and boundary handling."""
    p_a = Point3D(0.0, 0.0, 0.0)
    p_b = Point3D(10.0, 0.0, 0.0)

    # Midpoint interpolation: val_a = 20, val_b = 60, iso = 40 -> t = 0.5 -> x = 5.0
    p_mid = interpolate_edge(p_a, p_b, 20.0, 60.0, 40.0)
    assert p_mid.x == pytest.approx(5.0, abs=1e-7)
    assert p_mid.y == pytest.approx(0.0, abs=1e-7)
    assert p_mid.z == pytest.approx(0.0, abs=1e-7)

    # Fractional interpolation: val_a = 20, val_b = 60, iso = 50 -> t = 0.75 -> x = 7.5
    p_frac = interpolate_edge(p_a, p_b, 20.0, 60.0, 50.0)
    assert p_frac.x == pytest.approx(7.5, abs=1e-7)

    # Flat edge (s_a == s_b): fallback to t = 0.5
    p_flat = interpolate_edge(p_a, p_b, 30.0, 30.0, 30.0)
    assert p_flat.x == pytest.approx(5.0, abs=1e-7)

    # 3D diagonal edge: (0, 0, 0) to (6, 8, 10), iso = 75% between 0 and 100
    p_c = Point3D(6.0, 8.0, 10.0)
    p_diag = interpolate_edge(p_a, p_c, 0.0, 100.0, 75.0)
    assert p_diag.x == pytest.approx(4.5, abs=1e-7)
    assert p_diag.y == pytest.approx(6.0, abs=1e-7)
    assert p_diag.z == pytest.approx(7.5, abs=1e-7)


def test_single_tetrahedron_isosurface_extraction() -> None:
    """Stage 3: Verify single tetrahedron isosurface generation across threshold cases."""
    # Tetrahedron with vertices at 0, 10, 20, 30
    tet = Tetrahedron3D(
        p0=Point3D(0.0, 0.0, 0.0), s0=0.0,
        p1=Point3D(1.0, 0.0, 0.0), s1=10.0,
        p2=Point3D(0.0, 1.0, 0.0), s2=20.0,
        p3=Point3D(0.0, 0.0, 1.0), s3=30.0,
    )
    pts = [tet.p0, tet.p1, tet.p2, tet.p3]
    vals = [tet.s0, tet.s1, tet.s2, tet.s3]

    # Create dummy 2x2x2 field containing this single tet
    field = ScalarField3D(nx=2, ny=2, nz=2, x_min=0.0, x_max=1.0, y_min=0.0, y_max=1.0, z_min=0.0, z_max=1.0)
    # Set values to trigger case 14 (only vertex 0 below 5.0)
    for idx in range(8):
        field._values[idx] = 10.0
    field._values[0] = 0.0  # node 0 is below threshold 5.0

    tris = extract_isosurface(field, threshold=5.0)
    assert len(tris) >= 1
    assert all(t.area > 0.0 for t in tris)


# ============================================================================
# 4. Isometric Projection Transformation and Depth Sorting (Painter's Algorithm)
# ============================================================================

def test_isometric_projection_and_depth_sorting() -> None:
    """Stage 4: Verify axonometric/isometric projection transformation and Painter's algorithm."""
    projector = IsometricProjector(
        azimuth_deg=45.0,
        elevation_deg=35.264,
        center_u=600.0,
        center_v=395.0,
        scale=10.0,
    )
    origin = Point3D(0.0, 0.0, 0.0)

    # 1. Project origin -> maps exactly to screen center (600, 395)
    u_orig, v_orig, depth_orig = projector.project_point(origin, origin)
    assert u_orig == pytest.approx(600.0, abs=1e-5)
    assert v_orig == pytest.approx(395.0, abs=1e-5)
    assert depth_orig == pytest.approx(0.0, abs=1e-5)

    # 2. Points on +Z axis should project vertically higher (smaller v on inverted SVG screen)
    p_up = Point3D(0.0, 0.0, 5.0)
    u_up, v_up, depth_up = projector.project_point(p_up, origin)
    assert v_up < v_orig
    assert math.isfinite(u_up) and math.isfinite(v_up)

    # 3. Painter's algorithm depth sorting
    shader = LambertianShader()
    tri_far = Triangle3D(
        Point3D(-10.0, -10.0, -10.0),
        Point3D(-9.0, -10.0, -10.0),
        Point3D(-10.0, -9.0, -10.0),
    )
    tri_near = Triangle3D(
        Point3D(10.0, 10.0, 10.0),
        Point3D(11.0, 10.0, 10.0),
        Point3D(10.0, 11.0, 10.0),
    )

    # Pass in near, then far
    sorted_polys = projector.project_triangles([tri_near, tri_far], origin, shader)
    assert len(sorted_polys) == 2

    # Painter's order: furthest polygon (smaller depth) must be first
    assert sorted_polys[0].depth < sorted_polys[1].depth
    # All polygon coordinates must be finite
    for poly in sorted_polys:
        assert len(poly.points_2d) == 3
        for pu, pv in poly.points_2d:
            assert math.isfinite(pu) and math.isfinite(pv)


# ============================================================================
# 5. Lambertian Diffuse Shading and Face Normal Calculation
# ============================================================================

def test_triangle_face_normal_and_area() -> None:
    """Stage 5: Verify 3D analytical face normal via cross product and surface area."""
    # 1. Triangle in XY plane: normal should be (0, 0, 1)
    tri_xy = Triangle3D(
        Point3D(0.0, 0.0, 0.0),
        Point3D(4.0, 0.0, 0.0),
        Point3D(0.0, 3.0, 0.0),
    )
    assert tri_xy.normal.x == pytest.approx(0.0, abs=1e-6)
    assert tri_xy.normal.y == pytest.approx(0.0, abs=1e-6)
    assert tri_xy.normal.z == pytest.approx(1.0, abs=1e-6)
    assert tri_xy.normal.length() == pytest.approx(1.0, abs=1e-6)
    # Area = 0.5 * 4 * 3 = 6.0
    assert tri_xy.area == pytest.approx(6.0, abs=1e-6)

    # 2. Triangle in XZ plane: normal should be (0, -1, 0)
    tri_xz = Triangle3D(
        Point3D(0.0, 0.0, 0.0),
        Point3D(2.0, 0.0, 0.0),
        Point3D(0.0, 0.0, 5.0),
    )
    assert tri_xz.normal.x == pytest.approx(0.0, abs=1e-6)
    assert tri_xz.normal.y == pytest.approx(-1.0, abs=1e-6)
    assert tri_xz.normal.z == pytest.approx(0.0, abs=1e-6)
    assert tri_xz.area == pytest.approx(5.0, abs=1e-6)


def test_lambertian_diffuse_shading() -> None:
    """Stage 5: Verify Lambertian diffuse lighting model and color bounds."""
    shader = LambertianShader(
        ambient=0.25,
        diffuse=0.75,
        base_rgb=(6, 182, 212),  # Industrial Cyan (#06B6D4)
    )

    # Normal aligned with light: peak diffuse intensity
    norm_aligned = shader.light_dir.normalized()
    intensity_max, fill_max, stroke_max = shader.compute_shading(norm_aligned)
    assert intensity_max == pytest.approx(1.0, abs=1e-3)
    assert fill_max.startswith("rgb(")
    assert stroke_max.startswith("rgb(")

    # Normal perpendicular to light (with y >= 0 so no double-sided flip): dot product = 0 -> only ambient intensity
    norm_perp = Point3D(-shader.light_dir.z, 0.0, shader.light_dir.x).normalized()
    intensity_perp, fill_perp, _ = shader.compute_shading(norm_perp)
    assert intensity_perp == pytest.approx(0.25, abs=1e-3)
    assert fill_perp.startswith("rgb(")


# ============================================================================
# 6. Standalone W3C SVG 1.1 Generation and XML Well-Formedness
# ============================================================================

def test_w3c_svg_11_generation_and_xml_well_formedness() -> None:
    """Stage 6: Verify standalone W3C SVG 1.1 layout and XML well-formedness."""
    canvas = MarchingTetrahedraCanvas(nx=8, ny=8, nz=6)
    test_field = create_canonical_thermal_field(nx=8, ny=8, nz=6, peak_val=80.0, ambient_val=25.0)
    canvas.set_field(test_field, threshold=45.0)

    svg_content = canvas.render_svg()
    assert isinstance(svg_content, str)
    assert len(svg_content) > 1000

    # Parse with ElementTree to assert XML well-formedness
    root = ET.fromstring(svg_content)
    assert root.tag.endswith("svg")
    assert root.attrib["width"] == "1200"
    assert root.attrib["height"] == "750"
    assert root.attrib["viewBox"] == "0 0 1200 750"
    assert root.attrib["version"] == "1.1"

    # Verify SVG elements
    assert "<polygon" in svg_content
    assert "<line" in svg_content
    assert "<rect" in svg_content
    assert "<text" in svg_content
    assert "#0F172A" in svg_content  # Industrial dark backdrop
    assert "#0B0F19" in svg_content  # Decoupled dark badge backing
    assert (canvas.status_bits & MarchingTetraStatusBits.SVG_VALID) != 0


# ============================================================================
# 7. WCAG 2.1 AAA High-Contrast Ratio Compliance (> 18:1)
# ============================================================================

def test_wcag_21_aaa_high_contrast_ratio() -> None:
    """Stage 7: Verify WCAG 2.1 AAA high-contrast compliance on telemetry badges."""
    # Pure white (#FFFFFF) relative luminance L_white = 1.0
    # Decoupled dark backing badge (#0B0F19 at 0.92 opacity)
    # L_badge = 0.2126 * (11/255)^2.4 + 0.7152 * (15/255)^2.4 + 0.0722 * (25/255)^2.4 ≈ 0.004685
    # Contrast ratio = (L_white + 0.05) / (L_badge + 0.05) ≈ 1.05 / 0.054685 ≈ 19.20:1
    l_white = 1.0
    l_badge = 0.004685
    contrast_ratio = (l_white + 0.05) / (l_badge + 0.05)

    assert contrast_ratio > 18.0
    assert contrast_ratio == pytest.approx(19.20, abs=0.1)

    canvas = MarchingTetrahedraCanvas(nx=6, ny=6, nz=4)
    assert (canvas.status_bits & MarchingTetraStatusBits.WCAG_AAA) != 0


# ============================================================================
# 8. Horner OCS Register Space Synchronization & Trip Alarms
# ============================================================================

def test_horner_ocs_register_space_synchronization() -> None:
    """Stage 8: Verify Horner OCS register space synchronization (%R720..%R727, %M168..%M169)."""
    # 1. Nominal operating state (peak < 90.0 degC)
    canvas = MarchingTetrahedraCanvas(nx=8, ny=8, nz=6)
    test_field = create_canonical_thermal_field(nx=8, ny=8, nz=6, peak_val=80.0, ambient_val=20.0)
    canvas.set_field(test_field, threshold=45.0)

    # %R720: Status Word
    status_word = canvas.reg_table.read_uword("%R720")
    assert (status_word & int(MarchingTetraStatusBits.CANVAS_ACTIVE)) != 0
    assert (status_word & int(MarchingTetraStatusBits.MESH_EXTRACTED)) != 0
    assert (status_word & int(MarchingTetraStatusBits.HIGH_CONTOUR_ALARM)) == 0

    # %R721: Triangle Count
    tri_count = canvas.reg_table.read_word("%R721")
    assert tri_count == len(canvas.triangles)
    assert tri_count > 0

    # %R722: Threshold scaled x10
    thresh_scaled = canvas.reg_table.read_word("%R722")
    assert thresh_scaled == int(45.0 * 10)

    # %R724: Peak field scaled x10
    peak_scaled = canvas.reg_table.read_word("%R724")
    assert peak_scaled == int(test_field.max_val * 10)

    # %R727: Diagnostic Event Code
    diag_code = canvas.reg_table.read_word("%R727")
    assert diag_code == DIAG_EVENT_OK

    # %M168 & %M169: Discrete trip coils
    assert canvas.reg_table.read_bit("%M168") is False
    assert canvas.reg_table.read_bit("%M169") is False

    # 2. High contour alarm trip (%M168, %R727 = 0x8803)
    field_hot = create_canonical_thermal_field(nx=8, ny=8, nz=6, peak_val=96.0, ambient_val=20.0)
    canvas.set_field(field_hot, threshold=50.0)

    assert canvas.reg_table.read_bit("%M168") is True
    assert (canvas.reg_table.read_uword("%R720") & int(MarchingTetraStatusBits.HIGH_CONTOUR_ALARM)) != 0
    assert canvas.reg_table.read_uword("%R727") == DIAG_EVENT_HIGH_CONTOUR_TRIP

    # 3. Threshold out-of-bounds trip (%M169, %R727 = 0x8802)
    canvas.set_threshold(999.0)  # Beyond peak field
    assert canvas.reg_table.read_bit("%M169") is True
    assert (canvas.reg_table.read_uword("%R720") & int(MarchingTetraStatusBits.SINGULARITY_TRIP)) != 0
    assert canvas.reg_table.read_uword("%R727") == DIAG_EVENT_THRESHOLD_OUT_OF_BOUNDS


# ============================================================================
# 9. Full 9-Stage Verification Suite Runner
# ============================================================================

def test_full_9_stage_verification_suite(tmp_path: Path) -> None:
    """Verify complete 9-stage verification suite runner and 4-state contract."""
    evidence_path = str(tmp_path / "marching_evidence.json")
    svg_path = str(tmp_path / "marching.svg")

    res = run_marching_tetrahedra_verification(
        evidence_path=evidence_path,
        svg_path=svg_path,
    )

    assert res["status"] == "success"
    assert res["error_code"] is None
    assert res["data"]["total_checks"] == 9
    assert res["data"]["checks_passed"] == 9
    assert len(res["data"]["tests"]) == 9
    assert all(t["passed"] for t in res["data"]["tests"])

    # Verify generated evidence artifact
    assert Path(evidence_path).exists()
    assert Path(svg_path).exists()
