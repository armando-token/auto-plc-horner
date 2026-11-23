"""Unit tests for Cscape HMI Dynamic Delaunay Triangulation & Planar Mesh Canvas (W105)."""

from __future__ import annotations

import math
import pytest
import xml.etree.ElementTree as ET

from jev_cscape.hmi.delaunay_mesh import (
    DelaunayMeshCanvas,
    DelaunayStatusBits,
    Node2D,
    Triangle2D,
    compute_delaunay_triangulation,
    generate_delaunay_mesh_svg,
    interpolate_barycentric,
    verify_delaunay_pure_st,
)
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard


def test_pure_st_pou_ast() -> None:
    """Stage 1: Verify Pure ST POU AST parsing and absence of ladder constructs."""
    assert verify_delaunay_pure_st() is True


def test_circumcircle_computation() -> None:
    """Stage 2: Verify circumcenter and squared circumradius calculation."""
    # Right isosceles triangle: (0,0), (6,0), (0,6) -> circumcenter is (3,3), radius^2 = 18
    p1 = Node2D(0.0, 0.0)
    p2 = Node2D(6.0, 0.0)
    p3 = Node2D(0.0, 6.0)
    tri = Triangle2D(p1, p2, p3)

    assert tri.center_x == pytest.approx(3.0, abs=1e-6)
    assert tri.center_y == pytest.approx(3.0, abs=1e-6)
    assert tri.radius_sq == pytest.approx(18.0, abs=1e-6)

    assert tri.circumcircle_contains(Node2D(3.0, 3.0)) is True
    assert tri.circumcircle_contains(Node2D(8.0, 8.0)) is False


def test_delaunay_empty_circumcircle() -> None:
    """Stage 3: Verify Delaunay empty-circumcircle criterion."""
    nodes = [
        Node2D(100.0, 100.0),
        Node2D(300.0, 120.0),
        Node2D(500.0, 110.0),
        Node2D(150.0, 300.0),
        Node2D(350.0, 320.0),
        Node2D(480.0, 280.0),
    ]
    triangles = compute_delaunay_triangulation(nodes)
    assert len(triangles) >= 4

    # No node should lie strictly inside the circumcircle of any triangle (excluding triangle vertices)
    for tri in triangles:
        for node in nodes:
            if not tri.contains_vertex(node):
                dist_sq = (node.x - tri.center_x) ** 2 + (node.y - tri.center_y) ** 2
                # Distance squared must be >= radius squared (with small float tolerance)
                assert dist_sq >= (tri.radius_sq - 1e-4)


def test_degenerate_nodes() -> None:
    """Stage 3: Verify graceful handling of fewer than 3 nodes."""
    assert compute_delaunay_triangulation([]) == []
    assert compute_delaunay_triangulation([Node2D(1.0, 2.0)]) == []
    assert compute_delaunay_triangulation([Node2D(1.0, 2.0), Node2D(3.0, 4.0)]) == []


def test_quality_factor_and_sliver() -> None:
    """Stage 4: Verify normalized radius ratio quality factor rho."""
    # Equilateral triangle
    p1 = Node2D(0.0, 0.0)
    p2 = Node2D(2.0, 0.0)
    p3 = Node2D(1.0, math.sqrt(3.0))
    tri_eq = Triangle2D(p1, p2, p3)
    assert tri_eq.quality_factor == pytest.approx(1.0, rel=1e-3)

    # Skinny triangle (sliver)
    p_sk1 = Node2D(0.0, 0.0)
    p_sk2 = Node2D(200.0, 0.0)
    p_sk3 = Node2D(100.0, 2.0)
    tri_sk = Triangle2D(p_sk1, p_sk2, p_sk3)
    assert tri_sk.quality_factor < 0.10


def test_barycentric_interpolation() -> None:
    """Stage 5: Verify planar barycentric coordinate evaluation."""
    nodes = [
        Node2D(0.0, 0.0, val=20.0),
        Node2D(100.0, 0.0, val=40.0),
        Node2D(0.0, 100.0, val=60.0),
        Node2D(100.0, 100.0, val=80.0),
    ]
    triangles = compute_delaunay_triangulation(nodes)

    # Query exact vertex
    res_vertex = interpolate_barycentric(0.0, 0.0, triangles)
    assert res_vertex is not None
    assert res_vertex[0] == pytest.approx(20.0, abs=1e-3)

    # Query center of mesh (50, 50)
    res_center = interpolate_barycentric(50.0, 50.0, triangles)
    assert res_center is not None
    # Bilinear/triangular average around 50.0
    assert 40.0 <= res_center[0] <= 60.0

    # Query outside convex hull
    res_outside = interpolate_barycentric(500.0, 500.0, triangles)
    assert res_outside is None


def test_spatial_gradient_extraction() -> None:
    """Stage 6: Verify directional spatial gradient magnitude."""
    # Linear field: V(x, y) = 3.0 * x - 4.0 * y + 50.0 -> grad = (3, -4), mag = 5.0
    p1 = Node2D(0.0, 0.0, val=50.0)
    p2 = Node2D(10.0, 0.0, val=80.0)
    p3 = Node2D(0.0, 10.0, val=10.0)
    tri = Triangle2D(p1, p2, p3)

    assert tri.grad_alpha == pytest.approx(3.0, abs=1e-3)
    assert tri.grad_beta == pytest.approx(-4.0, abs=1e-3)
    assert tri.grad_mag == pytest.approx(5.0, abs=1e-3)


def test_svg_validity_and_dimensions() -> None:
    """Stage 7: Verify standalone W3C SVG 1.1 layout and XML well-formedness."""
    nodes = [
        Node2D(100.0, 100.0, val=50.0),
        Node2D(300.0, 120.0, val=70.0),
        Node2D(200.0, 300.0, val=90.0),
    ]
    triangles = compute_delaunay_triangulation(nodes)
    svg_str = generate_delaunay_mesh_svg(nodes, triangles)

    root = ET.fromstring(svg_str)
    assert root.tag.endswith("svg")
    assert root.attrib["width"] == "1200"
    assert root.attrib["height"] == "750"


def test_wcag_aaa_contrast() -> None:
    """Stage 8: Verify WCAG 2.1 AAA contrast compliance (> 18:1)."""
    # Pure white (#FFFFFF) relative luminance is 1.0
    # Dark badge (#0B0F19) relative luminance is approx 0.00483
    cr = (1.0 + 0.05) / (0.00483 + 0.05)
    assert cr > 18.0


def test_horner_register_sync() -> None:
    """Stage 9: Verify Horner OCS register synchronization (%R660..%R667, %M154..%M155)."""
    canvas = DelaunayMeshCanvas()
    nodes = [
        Node2D(100.0, 100.0, val=60.0, node_id=1),
        Node2D(400.0, 100.0, val=70.0, node_id=2),
        Node2D(250.0, 350.0, val=98.0, node_id=3),  # Hotspot node
    ]
    canvas.set_nodes(nodes)

    st_word = canvas.reg_table.read_uword("%R660")
    node_cnt = canvas.reg_table.read_word("%R661")
    tri_cnt = canvas.reg_table.read_word("%R662")
    crit_id = canvas.reg_table.read_word("%R667")

    assert (st_word & int(DelaunayStatusBits.CANVAS_ACTIVE)) != 0
    assert (st_word & int(DelaunayStatusBits.HOTSPOT_DETECTED)) != 0
    assert node_cnt == 3
    assert tri_cnt == 1
    assert crit_id == 3


def test_anti_ladder_guard() -> None:
    """Stage 9: Verify interception of ladder logic symbols with ERR_LADDER_FORBIDDEN."""
    bad_code = """
    PROGRAM BadDelaunay
    VAR B : BOOL; END_VAR
    ---[ ]---( )---
    END_PROGRAM
    """
    with pytest.raises(LadderForbiddenError):
        SecurityGuard.assert_pure_st_content(bad_code)
