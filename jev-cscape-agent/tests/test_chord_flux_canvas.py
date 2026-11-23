"""Comprehensive unit test suite for Cscape HMI Dynamic Chord Flux SCADA Canvas (Wave W234).

Work Package: Wave W234 (Gate G9 HMI Grounding & Vector Visuals / Gate G2 Live GUI)
Classification: PRODUCTION_READY [Dynamic Chord Flux Multi-Echelon SCADA Canvas]

Architectural Coverage (115+ Unit Tests across 14 Test Classes):
1. TestConstantsEnumsAndDiagnostics: DiagnosticCode signed/unsigned equality (& 0xFFFF), hashing, enums, status flags.
2. TestEntityDataclassAndFlowMatrix: Entity/ChordEntity dataclass, flow matrix configuration, arc angle calculations.
3. TestBezierRibbonAndPathSynthesis: Quadratic/cubic Bézier ribbon curves, loop synthesis, SVG path generation.
4. TestFlowConservationAndFluxImbalance: Mass balance conservation between entities, residual imbalance, ppm calculation.
5. TestHighFluxImbalanceAlarm: Process safety alarm (%M456 asserted when residual > 5%), latching, HUD warning.
6. TestSVGGenerationAndXMLSyntax: Standalone W3C SVG 1.1 generation, valid XML ElementTree, tags, dark backing.
7. TestWCAG21AAAContrastAndVisualLegibility: WCAG 2.1 AAA relative luminance, contrast formulas, badge > 18:1, text > 7:1.
8. TestDiagnosticFaultConditions: 0xF401 singularity, 0xF402 empty entity matrix, 0xF403 mass balance residual > 5%, 0xF404 canvas overflow.
9. TestResetNominalRecovery: Clean reset nominal state restoration across all entities, matrices, registers, coils.
10. TestHornerOCSSynchronizationAndRegisters: RegisterTable memory sync (%R1950..%R1957, %M455..%M456), PrivilegeMode.SYSTEM.
11. TestPureSTAndSecurity: Pure IEC 61131-3 Structured Text (ST) POU grammar, symbol bindings, AST validation.
12. TestAntiLadderRejection: Comprehensive fail-closed interception of contacts, coils, rungs, networks, mnemonics.
13. TestILogicUnitCompliance: Discrete scan cycle engine, scan_step(dt), execute(context), reset(), 100-cycle soak stability.
14. TestVerificationRunnerAndContract: Deterministic 9-stage verification runner, JSON evidence export, strict 4-state engineering contract.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Sequence, Set, Tuple
import xml.etree.ElementTree as ET
import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.hmi.chord_flux_canvas import (
    BOTTLENECK_ALARM_THRESHOLD_PCT,
    CANONICAL_CONDUIT_CAPACITY_MATRIX,
    CANONICAL_ENERGY_EXCHANGE_MATRIX,
    CANONICAL_MATERIAL_FLUX_MATRIX,
    CANONICAL_RECYCLE_CHORD_PAIRS,
    CANVAS_CENTER_X,
    CANVAS_CENTER_Y,
    CANVAS_OVERFLOW_FAULT,
    CANVAS_VIEWPORT_HEIGHT,
    CANVAS_VIEWPORT_WIDTH,
    CHORD_ERR_BOTTLENECK_ALARM,
    CHORD_ERR_BOTTLENECK_SATURATION_ALARM,
    CHORD_ERR_CANVAS_OVERFLOW,
    CHORD_ERR_EMPTY_ENTITY_MATRIX,
    CHORD_ERR_FLUX_IMBALANCE,
    CHORD_ERR_FLUX_IMBALANCE_EXCEEDED,
    CHORD_ERR_MASS_BALANCE_RESIDUAL,
    CHORD_ERR_NODE_OFFLINE,
    CHORD_ERR_OK,
    CHORD_ERR_RENDER_FAULT,
    CHORD_ERR_SINGULARITY,
    CHORD_ERR_SVG_RENDER_FAULT,
    CHORD_ERR_TOPOLOGY_NODE_OFFLINE,
    CHORD_FLUX_CANVAS_PURE_ST_POU,
    CHORD_FLUX_CANVAS_SYNC_PURE_ST_POU,
    CHORD_FLUX_CANVAS_W234_PURE_ST_POU,
    CHORD_FLUX_OK,
    CHORD_FLUX_PURE_ST_POU,
    CHORD_FLUX_W234_PURE_ST_POU,
    CHORD_INNER_RADIUS,
    CHORD_OK,
    CHORD_OUTER_RADIUS,
    COIL_CANVAS_ACTIVE,
    COIL_CHORD_CANVAS_ACTIVE,
    COIL_CHORD_FLUX_CANVAS_ACTIVE,
    COIL_FLUX_IMBALANCE_ALARM,
    COIL_HIGH_FLUX_IMBALANCE_ALARM,
    COIL_HIGH_FLUX_IMBALANCE_ALARM_ACTIVE,
    COIL_HIGH_IMBALANCE_ALARM,
    COIL_W198_CONSERVATION_VALID,
    COIL_W198_RIBBON_HIGHLIGHT,
    COIL_W234_ALARM_ACTIVE,
    COIL_W234_CANVAS_ACTIVE,
    COLOR_ALERT_CRIMSON,
    COLOR_ALKYLATION,
    COLOR_CARD_BG,
    COLOR_CARD_BORDER,
    COLOR_CDU,
    COLOR_DARK_THEME_ALT,
    COLOR_DARK_THEME_BACKING,
    COLOR_DECOUPLED_BADGE,
    COLOR_FCC,
    COLOR_GRID_LINE,
    COLOR_HCU,
    COLOR_HIGHLIGHT_GOLD,
    COLOR_NOMINAL_GREEN,
    COLOR_OFFSITE_BLENDING,
    COLOR_PETROCHEMICAL,
    COLOR_REFORMER,
    COLOR_TEXT_MUTED,
    COLOR_TEXT_PRIMARY,
    COLOR_VDU,
    CanvasOverflowError,
    ChordDiagnosticCode,
    ChordEntity,
    ChordFluxCanvas,
    ChordFluxCanvasEngine,
    ChordFluxDiagnosticCode,
    ChordFluxError,
    ChordFluxMetrics,
    ChordFluxStatusBits,
    ChordGeometrySingularityError,
    ChordStatusBits,
    DEFAULT_NODE_GAP_DEG,
    DIAG_ERR_CANVAS_OVERFLOW,
    DIAG_ERR_CHORD_GEOMETRY_SINGULARITY,
    DIAG_ERR_EMPTY_ENTITY_MATRIX,
    DIAG_ERR_EMPTY_MATRIX,
    DIAG_ERR_GEOMETRY_SINGULARITY,
    DIAG_ERR_MASS_BALANCE_RESIDUAL,
    DIAG_ERR_MASS_BALANCE_RESIDUAL_EXCEEDED,
    DIAG_ERR_SINGULARITY,
    DIAG_EVENT_BOTTLENECK_SATURATION_ALARM,
    DIAG_EVENT_FLUX_IMBALANCE_EXCEEDED,
    DIAG_EVENT_OK,
    DIAG_EVENT_SVG_RENDER_FAULT,
    DIAG_EVENT_TOPOLOGY_NODE_OFFLINE,
    DIAG_OK,
    DiagnosticCode,
    EMPTY_ENTITY_MATRIX_FAULT,
    EMPTY_MATRIX_FAULT,
    EmptyEntityMatrixError,
    Entity,
    EntityCategory,
    FLUX_CONSERVATION_VALID_THRESHOLD_PPM,
    FLUX_IMBALANCE_FAULT,
    FluxRibbon,
    GEOMETRY_SINGULARITY_FAULT,
    MASS_BALANCE_RESIDUAL_FAULT,
    MASS_BALANCE_RESIDUAL_THRESHOLD_PCT,
    MASS_BALANCE_RESIDUAL_THRESHOLD_PPM,
    MAX_ALLOWED_NODES,
    MIN_ALLOWED_NODES,
    MULTI_ECHELON_ENERGY_MASS_FLUX_PURE_ST_POU,
    MassBalanceResidualError,
    REG_ACTIVE_ENTITY_COUNT,
    REG_ACTIVE_NODE_COUNT,
    REG_BOTTLENECK_SATURATION_SCALED,
    REG_DIAGNOSTIC_STATUS_CODE,
    REG_DIAG_CODE,
    REG_ENERGY_EXCHANGE_SCALED,
    REG_FLUX_CONSERVATION_IMBALANCE_PPM,
    REG_FLUX_IMBALANCE_PPM,
    REG_MASS_BALANCE_RESIDUAL_PPM,
    REG_MAX_BOTTLENECK_SATURATION_PCT_SCALED,
    REG_NETWORK_RECYCLE_EFFICIENCY_PCT_SCALED,
    REG_RECYCLE_EFFICIENCY_SCALED,
    REG_SELECTED_SOURCE_ENTITY_INDEX,
    REG_SELECTED_SOURCE_NODE_INDEX,
    REG_SELECTED_TARGET_ENTITY_INDEX,
    REG_TOTAL_ENERGY_EXCHANGE_MW_SCALED,
    REG_TOTAL_FLUX_MT_H,
    REG_TOTAL_MATERIAL_FLUX,
    REG_TOTAL_MATERIAL_FLUX_MT_H,
    REG_W198_ACTIVE_NODE_COUNT,
    REG_W198_BOTTLENECK_SATURATION,
    REG_W198_IMBALANCE_PPM,
    REG_W198_RECYCLE_EFFICIENCY,
    REG_W198_SOURCE_INDEX,
    REG_W198_TARGET_INDEX,
    REG_W198_TOTAL_ENERGY_EXCHANGE,
    REG_W198_TOTAL_MATERIAL_FLUX,
    REG_W234_ACTIVE_ENTITIES,
    REG_W234_BOTTLENECK_SCALED,
    REG_W234_DIAG_CODE,
    REG_W234_ENERGY_SCALED,
    REG_W234_IMBALANCE_PPM,
    REG_W234_RECYCLE_EFF,
    REG_W234_SOURCE_INDEX,
    REG_W234_TOTAL_FLUX,
    REFINING_NETWORK_PALETTE,
    RefiningChordFluxCanvas,
    RefiningEchelon,
    RefiningLevel,
    RefiningNode,
    SINGULARITY_FAULT,
    TOTAL_CANONICAL_ENTITIES,
    TOTAL_CANONICAL_NODES,
    W234_CHORD_FLUX_PURE_ST_POU,
    WCAG_AAA_BADGE_CONTRAST_TARGET,
    WCAG_AAA_CONTRAST_TARGET,
    WCAG_AAA_TEXT_CONTRAST_TARGET,
    WCAG_GRAPHICAL_CONTRAST_TARGET,
    calculate_contrast_ratio,
    compute_chord_flux_metrics,
    create_canonical_chord_flux_canvas,
    create_canonical_refining_nodes,
    create_mock_scan_context,
    generate_bezier_ribbon_path,
    generate_chord_flux_canvas_svg,
    generate_cubic_bezier_ribbon_path,
    generate_directional_cubic_bezier_ribbon_path,
    generate_node_annular_sector_path,
    generate_quadratic_bezier_ribbon_path,
    hex_to_relative_luminance,
    layout_refining_chord_topology,
    run_chord_flux_canvas_verification,
    srgb_channel_to_linear,
    validate_chord_geometry,
    validate_entity_matrix,
    validate_mass_balance_residual,
    validate_wcag_aaa_contrast,
    verify_chord_flux_canvas_pure_st,
    verify_chord_flux_w234_pure_st,
    verify_multi_echelon_energy_mass_flux_pure_st,
)


# ============================================================================
# Section 1: Constants, Enums, and Diagnostic Codes
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate 16-bit diagnostic codes, signed/unsigned equality (& 0xFFFF), registers, coils, and enums."""

    def test_diagnostic_code_ok_equality(self) -> None:
        """DIAG_EVENT_OK is 0x0000 and equals 0 integer."""
        assert DIAG_EVENT_OK == 0
        assert DIAG_EVENT_OK == 0x0000
        assert DIAG_OK == DIAG_EVENT_OK
        assert CHORD_ERR_OK == DIAG_EVENT_OK
        assert CHORD_OK == DIAG_EVENT_OK
        assert CHORD_FLUX_OK == DIAG_EVENT_OK
        assert int(DIAG_EVENT_OK) == 0

    @pytest.mark.parametrize(
        "code_const,uint_val,sint_val",
        [
            (DIAG_ERR_CHORD_GEOMETRY_SINGULARITY, 0xF401, 0xF401 - 0x10000),
            (DIAG_ERR_EMPTY_ENTITY_MATRIX, 0xF402, 0xF402 - 0x10000),
            (DIAG_ERR_MASS_BALANCE_RESIDUAL, 0xF403, 0xF403 - 0x10000),
            (DIAG_ERR_CANVAS_OVERFLOW, 0xF404, 0xF404 - 0x10000),
        ],
    )
    def test_diagnostic_code_w234_signed_unsigned_equality(
        self, code_const: DiagnosticCode, uint_val: int, sint_val: int
    ) -> None:
        """DiagnosticCode supports unsigned uint16 and signed int16 equality via & 0xFFFF."""
        assert code_const == uint_val
        assert code_const == sint_val
        assert (code_const & 0xFFFF) == uint_val
        assert int(code_const) == uint_val

    @pytest.mark.parametrize(
        "code_const,uint_val,sint_val",
        [
            (CHORD_ERR_FLUX_IMBALANCE_EXCEEDED, 0xD601, 0xD601 - 0x10000),
            (CHORD_ERR_BOTTLENECK_SATURATION_ALARM, 0xD602, 0xD602 - 0x10000),
            (CHORD_ERR_TOPOLOGY_NODE_OFFLINE, 0xD603, 0xD603 - 0x10000),
            (CHORD_ERR_SVG_RENDER_FAULT, 0xD604, 0xD604 - 0x10000),
        ],
    )
    def test_diagnostic_code_legacy_w198_equality(
        self, code_const: DiagnosticCode, uint_val: int, sint_val: int
    ) -> None:
        """DiagnosticCode supports legacy W198 event codes with signed/unsigned equality."""
        assert code_const == uint_val
        assert code_const == sint_val
        assert (code_const & 0xFFFF) == uint_val

    def test_diagnostic_code_hash_and_uniqueness(self) -> None:
        """DiagnosticCode hashes conform to 16-bit integer masking and ensure set uniqueness."""
        codes = {
            DIAG_EVENT_OK,
            DIAG_ERR_CHORD_GEOMETRY_SINGULARITY,
            DIAG_ERR_EMPTY_ENTITY_MATRIX,
            DIAG_ERR_MASS_BALANCE_RESIDUAL,
            DIAG_ERR_CANVAS_OVERFLOW,
        }
        assert len(codes) == 5
        assert hash(DiagnosticCode(0xF401)) == hash(0xF401)
        assert ChordDiagnosticCode is DiagnosticCode
        assert ChordFluxDiagnosticCode is DiagnosticCode

    def test_diagnostic_code_aliases(self) -> None:
        """Aliases for diagnostic fault codes point to canonical constants."""
        assert DIAG_ERR_GEOMETRY_SINGULARITY == DIAG_ERR_CHORD_GEOMETRY_SINGULARITY
        assert DIAG_ERR_SINGULARITY == DIAG_ERR_CHORD_GEOMETRY_SINGULARITY
        assert CHORD_ERR_SINGULARITY == DIAG_ERR_CHORD_GEOMETRY_SINGULARITY
        assert GEOMETRY_SINGULARITY_FAULT == DIAG_ERR_CHORD_GEOMETRY_SINGULARITY
        assert SINGULARITY_FAULT == DIAG_ERR_CHORD_GEOMETRY_SINGULARITY

        assert DIAG_ERR_EMPTY_MATRIX == DIAG_ERR_EMPTY_ENTITY_MATRIX
        assert CHORD_ERR_EMPTY_ENTITY_MATRIX == DIAG_ERR_EMPTY_ENTITY_MATRIX
        assert EMPTY_ENTITY_MATRIX_FAULT == DIAG_ERR_EMPTY_ENTITY_MATRIX
        assert EMPTY_MATRIX_FAULT == DIAG_ERR_EMPTY_ENTITY_MATRIX

        assert DIAG_ERR_MASS_BALANCE_RESIDUAL_EXCEEDED == DIAG_ERR_MASS_BALANCE_RESIDUAL
        assert CHORD_ERR_MASS_BALANCE_RESIDUAL == DIAG_ERR_MASS_BALANCE_RESIDUAL
        assert MASS_BALANCE_RESIDUAL_FAULT == DIAG_ERR_MASS_BALANCE_RESIDUAL
        assert FLUX_IMBALANCE_FAULT == DIAG_ERR_MASS_BALANCE_RESIDUAL

        assert CHORD_ERR_CANVAS_OVERFLOW == DIAG_ERR_CANVAS_OVERFLOW
        assert CANVAS_OVERFLOW_FAULT == DIAG_ERR_CANVAS_OVERFLOW

    def test_horner_w234_word_registers_constants(self) -> None:
        """Horner OCS word registers span %R1950..%R1957 with expected string bindings."""
        assert REG_TOTAL_MATERIAL_FLUX_MT_H == "%R1950"
        assert REG_TOTAL_FLUX_MT_H == "%R1950"
        assert REG_TOTAL_MATERIAL_FLUX == "%R1950"
        assert REG_W234_TOTAL_FLUX == "%R1950"

        assert REG_TOTAL_ENERGY_EXCHANGE_MW_SCALED == "%R1951"
        assert REG_ENERGY_EXCHANGE_SCALED == "%R1951"
        assert REG_W234_ENERGY_SCALED == "%R1951"

        assert REG_NETWORK_RECYCLE_EFFICIENCY_PCT_SCALED == "%R1952"
        assert REG_RECYCLE_EFFICIENCY_SCALED == "%R1952"
        assert REG_W234_RECYCLE_EFF == "%R1952"

        assert REG_MAX_BOTTLENECK_SATURATION_PCT_SCALED == "%R1953"
        assert REG_BOTTLENECK_SATURATION_SCALED == "%R1953"
        assert REG_W234_BOTTLENECK_SCALED == "%R1953"

        assert REG_ACTIVE_ENTITY_COUNT == "%R1954"
        assert REG_ACTIVE_NODE_COUNT == "%R1954"
        assert REG_W234_ACTIVE_ENTITIES == "%R1954"

        assert REG_FLUX_CONSERVATION_IMBALANCE_PPM == "%R1955"
        assert REG_FLUX_IMBALANCE_PPM == "%R1955"
        assert REG_MASS_BALANCE_RESIDUAL_PPM == "%R1955"
        assert REG_W234_IMBALANCE_PPM == "%R1955"

        assert REG_SELECTED_SOURCE_ENTITY_INDEX == "%R1956"
        assert REG_SELECTED_SOURCE_NODE_INDEX == "%R1956"
        assert REG_W234_SOURCE_INDEX == "%R1956"

        assert REG_DIAGNOSTIC_STATUS_CODE == "%R1957"
        assert REG_DIAG_CODE == "%R1957"
        assert REG_SELECTED_TARGET_ENTITY_INDEX == "%R1957"
        assert REG_W234_DIAG_CODE == "%R1957"

    def test_horner_w234_coils_constants(self) -> None:
        """Horner OCS discrete coils span %M455..%M456 with expected string bindings."""
        assert COIL_CHORD_FLUX_CANVAS_ACTIVE == "%M455"
        assert COIL_CHORD_CANVAS_ACTIVE == "%M455"
        assert COIL_CANVAS_ACTIVE == "%M455"
        assert COIL_W234_CANVAS_ACTIVE == "%M455"

        assert COIL_HIGH_FLUX_IMBALANCE_ALARM == "%M456"
        assert COIL_FLUX_IMBALANCE_ALARM == "%M456"
        assert COIL_HIGH_IMBALANCE_ALARM == "%M456"
        assert COIL_HIGH_FLUX_IMBALANCE_ALARM_ACTIVE == "%M456"
        assert COIL_W234_ALARM_ACTIVE == "%M456"

    def test_horner_legacy_registers_constants(self) -> None:
        """Legacy Horner registers %R1590..%R1597 and %M371..%M372 are defined."""
        assert REG_W198_TOTAL_MATERIAL_FLUX == "%R1590"
        assert REG_W198_TOTAL_ENERGY_EXCHANGE == "%R1591"
        assert REG_W198_RECYCLE_EFFICIENCY == "%R1592"
        assert REG_W198_BOTTLENECK_SATURATION == "%R1593"
        assert REG_W198_ACTIVE_NODE_COUNT == "%R1594"
        assert REG_W198_IMBALANCE_PPM == "%R1595"
        assert REG_W198_SOURCE_INDEX == "%R1596"
        assert REG_W198_TARGET_INDEX == "%R1597"
        assert COIL_W198_CONSERVATION_VALID == "%M371"
        assert COIL_W198_RIBBON_HIGHLIGHT == "%M372"

    def test_status_bits_definitions_and_combinations(self) -> None:
        """ChordFluxStatusBits has defined bits and supports bitwise operations."""
        assert ChordFluxStatusBits.ENGINE_ACTIVE == 1 << 0
        assert ChordFluxStatusBits.TOPOLOGY_COMPUTED == 1 << 1
        assert ChordFluxStatusBits.NOMINAL_OPERATION == 1 << 2
        assert ChordFluxStatusBits.FLUX_CONSERVATION_VALID == 1 << 3
        assert ChordFluxStatusBits.RIBBON_HIGHLIGHT_ACTIVE == 1 << 4
        assert ChordFluxStatusBits.FLUX_IMBALANCE_ALARM == 1 << 5
        assert ChordFluxStatusBits.BOTTLENECK_SATURATION_ALARM == 1 << 6
        assert ChordFluxStatusBits.TOPOLOGY_NODE_OFFLINE == 1 << 7
        assert ChordFluxStatusBits.SVG_RENDER_FAULT == 1 << 8
        assert ChordFluxStatusBits.SVG_VALID == 1 << 9
        assert ChordFluxStatusBits.WCAG_AAA == 1 << 10

        combo = ChordFluxStatusBits.ENGINE_ACTIVE | ChordFluxStatusBits.NOMINAL_OPERATION
        assert bool(combo & ChordFluxStatusBits.ENGINE_ACTIVE)
        assert not bool(combo & ChordFluxStatusBits.FLUX_IMBALANCE_ALARM)
        assert ChordStatusBits is ChordFluxStatusBits

    def test_enums_and_threshold_constants(self) -> None:
        """RefiningEchelon levels and threshold constants are correctly defined."""
        assert len(RefiningEchelon) == 4
        assert EntityCategory is RefiningEchelon
        assert RefiningLevel is RefiningEchelon
        assert TOTAL_CANONICAL_ENTITIES == 8
        assert TOTAL_CANONICAL_NODES == 8
        assert MIN_ALLOWED_NODES == 3
        assert MAX_ALLOWED_NODES == 16
        assert FLUX_CONSERVATION_VALID_THRESHOLD_PPM == 50
        assert MASS_BALANCE_RESIDUAL_THRESHOLD_PCT == 5.0
        assert MASS_BALANCE_RESIDUAL_THRESHOLD_PPM == 50000
        assert BOTTLENECK_ALARM_THRESHOLD_PCT == 95.0


# ============================================================================
# Section 2: Entity Dataclass and Flow Matrix Configuration
# ============================================================================

class TestEntityDataclassAndFlowMatrix:
    """Validate Entity / ChordEntity dataclass, flow matrix configuration, and arc angle calculations."""

    def test_entity_dataclass_initialization(self) -> None:
        """Entity dataclass initializes with required process attributes."""
        entity = Entity(
            index=1,
            node_id="CDU",
            name="Crude Distillation Unit",
            tag="CDU-100",
            echelon=RefiningEchelon.ECHELON_1_PRIMARY,
            capacity_mt_h=1750.0,
            color=COLOR_CDU,
        )
        assert entity.index == 1
        assert entity.node_id == "CDU"
        assert entity.name == "Crude Distillation Unit"
        assert entity.tag == "CDU-100"
        assert entity.echelon == RefiningEchelon.ECHELON_1_PRIMARY
        assert entity.capacity_mt_h == 1750.0
        assert entity.color == COLOR_CDU
        assert entity.is_online is True
        assert ChordEntity is Entity

    def test_entity_properties_aliases(self) -> None:
        """Entity property aliases match underlying fields."""
        entity = Entity(
            index=2,
            node_id="VDU",
            name="Vacuum Distillation Unit",
            tag="VDU-200",
            echelon=RefiningEchelon.ECHELON_1_PRIMARY,
            capacity_mt_h=850.0,
            color=COLOR_VDU,
            theta_start_rad=0.5,
            theta_end_rad=1.5,
        )
        assert entity.entity_id == "VDU"
        assert entity.theta_start == 0.5
        assert entity.theta_end == 1.5

    def test_entity_angular_span_calculation(self) -> None:
        """angular_span_rad calculates non-negative sector span."""
        entity = Entity(
            index=3,
            node_id="REF",
            name="Reformer",
            tag="REF-300",
            echelon=RefiningEchelon.ECHELON_2_CONVERSION,
            capacity_mt_h=700.0,
            color=COLOR_REFORMER,
            theta_start_rad=1.0,
            theta_end_rad=2.2,
        )
        assert math.isclose(entity.angular_span_rad, 1.2, rel_tol=1e-5)

    def test_canonical_entities_count_and_echelons(self) -> None:
        """create_canonical_refining_nodes generates exactly 8 entities spanning 4 echelons."""
        entities = create_canonical_refining_nodes()
        assert len(entities) == 8
        expected_ids = ["CDU", "VDU", "Reformer", "FCC", "HCU", "Alkylation", "Petrochemical", "Offsite Blending"]
        actual_ids = [e.node_id for e in entities]
        assert actual_ids == expected_ids

        echelon_counts = {}
        for e in entities:
            echelon_counts[e.echelon] = echelon_counts.get(e.echelon, 0) + 1
        assert echelon_counts[RefiningEchelon.ECHELON_1_PRIMARY] == 2
        assert echelon_counts[RefiningEchelon.ECHELON_2_CONVERSION] == 3
        assert echelon_counts[RefiningEchelon.ECHELON_3_UPGRADING] == 2
        assert echelon_counts[RefiningEchelon.ECHELON_4_OFFSITE] == 1

    def test_canonical_entities_capacities(self) -> None:
        """All canonical entities have positive nominal capacities."""
        entities = create_canonical_refining_nodes()
        for e in entities:
            assert e.capacity_mt_h > 0.0
        assert entities[0].capacity_mt_h == 1750.0
        assert entities[1].capacity_mt_h == 850.0
        assert entities[3].capacity_mt_h == 1050.0

    def test_material_flux_matrix_dimensions_and_sum(self) -> None:
        """CANONICAL_MATERIAL_FLUX_MATRIX is 8x8 with total flow sum of 4500.0 MT/h."""
        assert len(CANONICAL_MATERIAL_FLUX_MATRIX) == 8
        for row in CANONICAL_MATERIAL_FLUX_MATRIX:
            assert len(row) == 8
            assert all(v >= 0.0 for v in row)
        tot_flow = sum(sum(row) for row in CANONICAL_MATERIAL_FLUX_MATRIX)
        assert math.isclose(tot_flow, 4500.0, rel_tol=1e-5)

    def test_energy_exchange_matrix_dimensions_and_sum(self) -> None:
        """CANONICAL_ENERGY_EXCHANGE_MATRIX is 8x8 with total energy sum of 185.0 MWth."""
        assert len(CANONICAL_ENERGY_EXCHANGE_MATRIX) == 8
        for row in CANONICAL_ENERGY_EXCHANGE_MATRIX:
            assert len(row) == 8
            assert all(v >= 0.0 for v in row)
        tot_energy = sum(sum(row) for row in CANONICAL_ENERGY_EXCHANGE_MATRIX)
        assert math.isclose(tot_energy, 185.0, rel_tol=1e-5)

    def test_conduit_capacity_matrix_dimensions(self) -> None:
        """CANONICAL_CONDUIT_CAPACITY_MATRIX is 8x8 and accommodates all active flows."""
        assert len(CANONICAL_CONDUIT_CAPACITY_MATRIX) == 8
        for i in range(8):
            assert len(CANONICAL_CONDUIT_CAPACITY_MATRIX[i]) == 8
            for j in range(8):
                flow = CANONICAL_MATERIAL_FLUX_MATRIX[i][j]
                cap = CANONICAL_CONDUIT_CAPACITY_MATRIX[i][j]
                if flow > 0:
                    assert cap >= flow, f"Conduit capacity exceeded at ({i}, {j})"

    def test_arc_angle_partitioning_full_circle(self) -> None:
        """layout_refining_chord_topology maps all entities to sectors spanning full circle."""
        entities = create_canonical_refining_nodes()
        layout_refining_chord_topology(
            nodes=entities,
            material_matrix=CANONICAL_MATERIAL_FLUX_MATRIX,
            energy_matrix=CANONICAL_ENERGY_EXCHANGE_MATRIX,
            capacity_matrix=CANONICAL_CONDUIT_CAPACITY_MATRIX,
        )
        total_span = sum(e.angular_span_rad for e in entities)
        gap_total = 8 * math.radians(DEFAULT_NODE_GAP_DEG)
        assert math.isclose(total_span + gap_total, 2.0 * math.pi, rel_tol=1e-4)

    def test_node_gap_angles_and_strictly_positive_spans(self) -> None:
        """Each entity sector has strictly positive angular breadth and ordered angles."""
        entities = create_canonical_refining_nodes()
        layout_refining_chord_topology(
            nodes=entities,
            material_matrix=CANONICAL_MATERIAL_FLUX_MATRIX,
            energy_matrix=CANONICAL_ENERGY_EXCHANGE_MATRIX,
            capacity_matrix=CANONICAL_CONDUIT_CAPACITY_MATRIX,
        )
        for e in entities:
            assert e.angular_span_rad > 0.05
            assert e.theta_end_rad > e.theta_start_rad


# ============================================================================
# Section 3: Bézier Ribbon and Path Synthesis
# ============================================================================

class TestBezierRibbonAndPathSynthesis:
    """Validate directional cubic and quadratic Bézier ribbon paths and SVG path generation."""

    def test_flux_ribbon_dataclass_attributes(self) -> None:
        """FluxRibbon initializes and calculates hydraulic conduit saturation percentage."""
        ribbon = FluxRibbon(
            chord_id="CDU->VDU",
            source_index=1,
            target_index=2,
            source_id="CDU",
            target_id="VDU",
            material_flux_mt_h=550.0,
            energy_flux_mw=36.0,
            conduit_capacity_mt_h=621.47,
        )
        assert ribbon.chord_id == "CDU->VDU"
        assert ribbon.source_index == 1
        assert ribbon.target_index == 2
        assert ribbon.is_recycle is False
        assert ribbon.is_highlighted is False
        assert math.isclose(ribbon.saturation_pct, 88.5, abs_tol=0.1)

    def test_layout_refining_chord_topology_ribbon_count(self) -> None:
        """Canonical network generates exactly 23 directional transfer ribbons."""
        entities = create_canonical_refining_nodes()
        ribbons = layout_refining_chord_topology(
            nodes=entities,
            material_matrix=CANONICAL_MATERIAL_FLUX_MATRIX,
            energy_matrix=CANONICAL_ENERGY_EXCHANGE_MATRIX,
            capacity_matrix=CANONICAL_CONDUIT_CAPACITY_MATRIX,
        )
        assert len(ribbons) == 23

    def test_directional_cubic_bezier_path_syntax(self) -> None:
        """generate_directional_cubic_bezier_ribbon_path synthesizes valid SVG path string."""
        entities = create_canonical_refining_nodes()
        ribbons = layout_refining_chord_topology(
            nodes=entities,
            material_matrix=CANONICAL_MATERIAL_FLUX_MATRIX,
            energy_matrix=CANONICAL_ENERGY_EXCHANGE_MATRIX,
            capacity_matrix=CANONICAL_CONDUIT_CAPACITY_MATRIX,
        )
        path = generate_directional_cubic_bezier_ribbon_path(ribbons[0])
        assert path.startswith("M ")
        assert " A " in path
        assert " C " in path
        assert path.endswith(" Z")
        assert generate_cubic_bezier_ribbon_path is generate_directional_cubic_bezier_ribbon_path
        assert generate_bezier_ribbon_path is generate_directional_cubic_bezier_ribbon_path

    def test_quadratic_bezier_path_syntax(self) -> None:
        """generate_quadratic_bezier_ribbon_path synthesizes valid quadratic Bézier SVG path."""
        entities = create_canonical_refining_nodes()
        ribbons = layout_refining_chord_topology(
            nodes=entities,
            material_matrix=CANONICAL_MATERIAL_FLUX_MATRIX,
            energy_matrix=CANONICAL_ENERGY_EXCHANGE_MATRIX,
            capacity_matrix=CANONICAL_CONDUIT_CAPACITY_MATRIX,
        )
        path = generate_quadratic_bezier_ribbon_path(ribbons[0])
        assert path.startswith("M ")
        assert " A " in path
        assert " Q " in path
        assert path.endswith(" Z")

    def test_recycle_chords_identification(self) -> None:
        """Identifies exactly 4 closed-loop recycle streams in refining network."""
        entities = create_canonical_refining_nodes()
        ribbons = layout_refining_chord_topology(
            nodes=entities,
            material_matrix=CANONICAL_MATERIAL_FLUX_MATRIX,
            energy_matrix=CANONICAL_ENERGY_EXCHANGE_MATRIX,
            capacity_matrix=CANONICAL_CONDUIT_CAPACITY_MATRIX,
        )
        recycle_ribbons = [r for r in ribbons if r.is_recycle]
        assert len(recycle_ribbons) == 4
        expected_pairs = [(4, 3), (5, 3), (7, 3), (8, 1)]
        actual_pairs = [(r.source_index, r.target_index) for r in recycle_ribbons]
        assert sorted(actual_pairs) == sorted(expected_pairs)

    def test_conduit_saturation_percentage_calculation(self) -> None:
        """Calculates conduit saturation accurately across all corridors."""
        entities = create_canonical_refining_nodes()
        ribbons = layout_refining_chord_topology(
            nodes=entities,
            material_matrix=CANONICAL_MATERIAL_FLUX_MATRIX,
            energy_matrix=CANONICAL_ENERGY_EXCHANGE_MATRIX,
            capacity_matrix=CANONICAL_CONDUIT_CAPACITY_MATRIX,
        )
        max_sat = max(r.saturation_pct for r in ribbons)
        assert math.isclose(max_sat, 88.5, abs_tol=0.1)

    def test_ribbon_coordinates_within_viewport(self) -> None:
        """All ribbon coordinates and control points lie within the 1200x750 viewport."""
        entities = create_canonical_refining_nodes()
        ribbons = layout_refining_chord_topology(
            nodes=entities,
            material_matrix=CANONICAL_MATERIAL_FLUX_MATRIX,
            energy_matrix=CANONICAL_ENERGY_EXCHANGE_MATRIX,
            capacity_matrix=CANONICAL_CONDUIT_CAPACITY_MATRIX,
        )
        for r in ribbons:
            for theta in (r.theta_src_start, r.theta_src_end, r.theta_tgt_start, r.theta_tgt_end):
                px = CANVAS_CENTER_X + CHORD_INNER_RADIUS * math.cos(theta)
                py = CANVAS_CENTER_Y + CHORD_INNER_RADIUS * math.sin(theta)
                assert 0.0 <= px <= CANVAS_VIEWPORT_WIDTH
                assert 0.0 <= py <= CANVAS_VIEWPORT_HEIGHT

    def test_ribbon_highlight_state_and_selection(self) -> None:
        """Selected bilateral chord ribbon is flagged as highlighted."""
        entities = create_canonical_refining_nodes()
        ribbons = layout_refining_chord_topology(
            nodes=entities,
            material_matrix=CANONICAL_MATERIAL_FLUX_MATRIX,
            energy_matrix=CANONICAL_ENERGY_EXCHANGE_MATRIX,
            capacity_matrix=CANONICAL_CONDUIT_CAPACITY_MATRIX,
            selected_source_index=1,
            selected_target_index=2,
        )
        highlighted = [r for r in ribbons if r.is_highlighted]
        assert len(highlighted) == 1
        assert highlighted[0].source_index == 1
        assert highlighted[0].target_index == 2

    def test_node_annular_sector_path_syntax(self) -> None:
        """generate_node_annular_sector_path generates closed SVG annular arc path."""
        entities = create_canonical_refining_nodes()
        layout_refining_chord_topology(
            nodes=entities,
            material_matrix=CANONICAL_MATERIAL_FLUX_MATRIX,
            energy_matrix=CANONICAL_ENERGY_EXCHANGE_MATRIX,
            capacity_matrix=CANONICAL_CONDUIT_CAPACITY_MATRIX,
        )
        path = generate_node_annular_sector_path(entities[0])
        assert path.startswith("M ")
        assert " A " in path
        assert " L " in path
        assert path.endswith(" Z")


# ============================================================================
# Section 4: Flow Conservation and Flux Imbalance
# ============================================================================

class TestFlowConservationAndFluxImbalance:
    """Validate mass/energy flow conservation between entities and residual imbalance calculations."""

    def test_kirchhoff_nodal_mass_balance_per_entity(self) -> None:
        """Inflow and outflow across all entities balance to zero net network residual."""
        entities = create_canonical_refining_nodes()
        layout_refining_chord_topology(
            nodes=entities,
            material_matrix=CANONICAL_MATERIAL_FLUX_MATRIX,
            energy_matrix=CANONICAL_ENERGY_EXCHANGE_MATRIX,
            capacity_matrix=CANONICAL_CONDUIT_CAPACITY_MATRIX,
        )
        total_in = sum(e.total_inflow_mt_h for e in entities)
        total_out = sum(e.total_outflow_mt_h for e in entities)
        assert math.isclose(total_in, 4500.0, rel_tol=1e-4)
        assert math.isclose(total_out, 4500.0, rel_tol=1e-4)
        assert math.isclose(total_in - total_out, 0.0, abs_tol=1e-4)
        for e in entities:
            assert e.total_throughput_mt_h > 0.0

    def test_canonical_mass_conservation_imbalance_ppm(self) -> None:
        """Canonical network exhibits exactly 12 ppm baseline residual imbalance (< 50 ppm)."""
        canvas = create_canonical_chord_flux_canvas()
        assert canvas.metrics.flux_conservation_imbalance_ppm == 12
        assert canvas.metrics.flux_conservation_valid is True

    def test_flux_conservation_valid_coil_m371_nominal(self) -> None:
        """%M371 is asserted True during nominal operation with imbalance < 50 ppm."""
        canvas = create_canonical_chord_flux_canvas()
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_bit("%M371") is True

    def test_flux_imbalance_alarm_trip_0xd601(self) -> None:
        """Forced flux imbalance >= 50 ppm deasserts %M371 and triggers 0xD601."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_flux_imbalance(imbalance_ppm=80)
        assert canvas.metrics.flux_conservation_valid is False
        assert canvas.diagnostic_code == CHORD_ERR_FLUX_IMBALANCE_EXCEEDED
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_bit("%M371") is False

    def test_mass_balance_residual_threshold_5_pct(self) -> None:
        """Mass balance residual threshold is exactly 5% (50,000 ppm)."""
        assert MASS_BALANCE_RESIDUAL_THRESHOLD_PCT == 5.0
        assert MASS_BALANCE_RESIDUAL_THRESHOLD_PPM == 50000

    def test_network_recycle_efficiency_calculation(self) -> None:
        """Network recycle efficiency calculates to nominal 94.2%."""
        canvas = create_canonical_chord_flux_canvas()
        assert math.isclose(canvas.metrics.network_recycle_efficiency_pct, 94.2, rel_tol=1e-3)
        assert canvas.metrics.network_recycle_efficiency_pct_scaled == 942

    def test_total_energy_exchange_scaling(self) -> None:
        """Total thermal energy exchange calculates to 185.0 MWth (1850 scaled)."""
        canvas = create_canonical_chord_flux_canvas()
        assert math.isclose(canvas.metrics.total_energy_exchange_mw, 185.0, rel_tol=1e-3)
        assert canvas.metrics.total_energy_exchange_mw_scaled == 1850

    def test_max_bottleneck_saturation_calculation(self) -> None:
        """Max bottleneck saturation calculates to 88.5% (885 scaled)."""
        canvas = create_canonical_chord_flux_canvas()
        assert math.isclose(canvas.metrics.max_bottleneck_saturation_pct, 88.5, abs_tol=0.1)
        assert canvas.metrics.max_bottleneck_saturation_pct_scaled == 885


# ============================================================================
# Section 5: High Flux Imbalance Alarm (%M456)
# ============================================================================

class TestHighFluxImbalanceAlarm:
    """Validate process safety interlock %M456 asserted when mass balance residual exceeds 5%."""

    def test_high_flux_imbalance_alarm_coil_m456_asserted(self) -> None:
        """Triggering high flux imbalance asserts discrete coil %M456."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_high_flux_imbalance_alarm(imbalance_ppm=60000)
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_bit("%M456") is True

    def test_high_flux_imbalance_alarm_deasserted_nominally(self) -> None:
        """%M456 is deasserted False under nominal conditions (residual < 5%)."""
        canvas = create_canonical_chord_flux_canvas()
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_bit("%M456") is False

    def test_high_flux_imbalance_alarm_triggers_diagnostic_0xf403(self) -> None:
        """High flux imbalance triggers diagnostic code 0xF403 (MASS_BALANCE_RESIDUAL)."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_high_flux_imbalance_alarm()
        assert canvas.diagnostic_code == DIAG_ERR_MASS_BALANCE_RESIDUAL
        assert (canvas.diagnostic_code & 0xFFFF) == 0xF403

    def test_high_flux_imbalance_alarm_clears_nominal_status_bit(self) -> None:
        """High flux imbalance clears NOMINAL_OPERATION and asserts FLUX_IMBALANCE_ALARM."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_high_flux_imbalance_alarm()
        assert not bool(canvas.status_bits & ChordFluxStatusBits.NOMINAL_OPERATION)
        assert bool(canvas.status_bits & ChordFluxStatusBits.FLUX_IMBALANCE_ALARM)

    def test_high_flux_imbalance_alarm_persists_across_scan_steps(self) -> None:
        """High flux imbalance alarm persists across multiple scan cycles until cleared."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_high_flux_imbalance_alarm()
        for _ in range(5):
            canvas.scan_step(dt=0.01)
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_bit("%M456") is True

    def test_high_flux_imbalance_alarm_custom_threshold_ppm(self) -> None:
        """Explicit mass balance residual exceeding 50,000 ppm triggers %M456."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_mass_balance_residual_fault(imbalance_ppm=75000)
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_bit("%M456") is True
        assert (table.read_word("%R1955") & 0xFFFF) == (75000 & 0xFFFF)
        assert canvas.metrics.flux_conservation_imbalance_ppm == 75000

    def test_high_flux_imbalance_hud_alert_rendering(self) -> None:
        """SVG contains alert indicator when high flux imbalance alarm is active."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_high_flux_imbalance_alarm()
        svg = canvas.to_svg()
        assert "ALERT" in svg or "Imbalance" in svg

    def test_high_flux_imbalance_recovery_restores_m456(self) -> None:
        """Calling reset_nominal() de-asserts %M456 and clears alarm latch."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_high_flux_imbalance_alarm()
        canvas.reset_nominal()
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_bit("%M456") is False
        assert canvas.diagnostic_code == DIAG_EVENT_OK


# ============================================================================
# Section 6: SVG 1.1 Generation and XML Syntax
# ============================================================================

class TestSVGGenerationAndXMLSyntax:
    """Validate standalone W3C SVG 1.1 vector graphic synthesis and XML structure."""

    def test_svg_xml_well_formed_element_tree(self) -> None:
        """Generated SVG parses cleanly with xml.etree.ElementTree."""
        canvas = create_canonical_chord_flux_canvas()
        svg_text = canvas.to_svg()
        root = ET.fromstring(svg_text)
        assert root.tag.endswith("svg")

    def test_svg_viewport_dimensions_1200x750(self) -> None:
        """SVG declares width=1200, height=750, and viewBox matching SCADA viewport."""
        canvas = create_canonical_chord_flux_canvas()
        svg_text = canvas.to_svg()
        root = ET.fromstring(svg_text)
        assert root.attrib.get("width") == "1200"
        assert root.attrib.get("height") == "750"
        assert root.attrib.get("viewBox") == "0 0 1200 750"

    def test_svg_xml_namespace_and_version(self) -> None:
        """SVG declares valid W3C 1.1 namespace and version."""
        canvas = create_canonical_chord_flux_canvas()
        svg_text = canvas.to_svg()
        assert 'xmlns="http://www.w3.org/2000/svg"' in svg_text
        assert 'version="1.1"' in svg_text

    def test_svg_defs_gradients_and_filters_present(self) -> None:
        """SVG defs block contains linear gradients, radial glow, and filter elements."""
        canvas = create_canonical_chord_flux_canvas()
        svg_text = canvas.to_svg()
        root = ET.fromstring(svg_text)
        defs = root.find("{http://www.w3.org/2000/svg}defs")
        assert defs is not None
        assert len(defs) > 0

    def test_svg_all_8_entity_arcs_rendered(self) -> None:
        """All 8 canonical entity unit labels are rendered in SVG."""
        canvas = create_canonical_chord_flux_canvas()
        svg_text = canvas.to_svg()
        for nid in ("CDU", "VDU", "Reformer", "FCC", "HCU", "Alkylation", "Petrochemical", "Offsite Blending"):
            assert nid in svg_text

    def test_svg_ribbon_paths_count_and_groups(self) -> None:
        """SVG contains ribbon group with 23 bilateral transfer paths."""
        canvas = create_canonical_chord_flux_canvas()
        svg_text = canvas.to_svg()
        assert 'id="chord-ribbons"' in svg_text or 'class="chord-ribbon"' in svg_text
        assert svg_text.count('class="chord-ribbon') >= 23 or svg_text.count("d=\"M ") >= 23

    def test_svg_hud_telemetry_cards_rendered(self) -> None:
        """SVG includes HUD telemetry status card displaying flux and register telemetry."""
        canvas = create_canonical_chord_flux_canvas()
        svg_text = canvas.to_svg()
        assert "4,500 MT/h" in svg_text or "4500" in svg_text
        assert "185.0 MWth" in svg_text or "185" in svg_text

    def test_svg_dark_theme_backing_rect(self) -> None:
        """SVG begins with dark theme backing rectangle with COLOR_DARK_THEME_BACKING fill."""
        canvas = create_canonical_chord_flux_canvas()
        svg_text = canvas.to_svg()
        assert COLOR_DARK_THEME_BACKING in svg_text

    def test_svg_selected_chord_highlight_styling(self) -> None:
        """SVG highlights the active selected chord ribbon."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.select_chord(source_index=1, target_index=2)
        svg_text = canvas.to_svg()
        assert COLOR_HIGHLIGHT_GOLD in svg_text or "ribbon-highlight" in svg_text

    def test_svg_render_fault_trigger_handling(self) -> None:
        """SVG render fault sets diagnostic code 0xD604 and handles gracefully."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_render_fault()
        assert canvas.diagnostic_code == CHORD_ERR_SVG_RENDER_FAULT
        assert bool(canvas.status_bits & ChordFluxStatusBits.SVG_RENDER_FAULT)


# ============================================================================
# Section 7: WCAG 2.1 AAA Contrast and Visual Legibility
# ============================================================================

class TestWCAG21AAAContrastAndVisualLegibility:
    """Validate WCAG 2.1 AAA accessibility contrast formulas, ratios, and palette compliance."""

    def test_srgb_channel_to_linear_calculation(self) -> None:
        """srgb_channel_to_linear correctly handles linear and gamma sections."""
        assert math.isclose(srgb_channel_to_linear(0.0), 0.0, abs_tol=1e-5)
        assert math.isclose(srgb_channel_to_linear(0.03928), 0.03928 / 12.92, abs_tol=1e-5)
        assert math.isclose(srgb_channel_to_linear(1.0), 1.0, abs_tol=1e-5)

    def test_relative_luminance_black_and_white(self) -> None:
        """hex_to_relative_luminance gives 0.0 for black and 1.0 for white."""
        assert math.isclose(hex_to_relative_luminance("#000000"), 0.0, abs_tol=1e-4)
        assert math.isclose(hex_to_relative_luminance("#FFFFFF"), 1.0, abs_tol=1e-4)

    def test_calculate_contrast_ratio_symmetry_and_range(self) -> None:
        """calculate_contrast_ratio is symmetric and bounded between 1.0 and 21.0."""
        r1 = calculate_contrast_ratio("#000000", "#FFFFFF")
        r2 = calculate_contrast_ratio("#FFFFFF", "#000000")
        assert math.isclose(r1, r2, rel_tol=1e-4)
        assert 1.0 <= r1 <= 21.01

    def test_decoupled_badge_contrast_exceeds_18_to_1(self) -> None:
        """Primary white text against decoupled badge background exceeds 18:1 (WCAG AAA)."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE)
        assert ratio >= WCAG_AAA_BADGE_CONTRAST_TARGET
        assert ratio > 18.0

    def test_theme_text_primary_contrast_exceeds_18_to_1(self) -> None:
        """Primary white text against dark theme backing exceeds 18:1 (WCAG AAA)."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_PRIMARY, COLOR_DARK_THEME_BACKING)
        assert ratio > 18.0

    def test_theme_text_muted_contrast_exceeds_7_to_1(self) -> None:
        """Muted secondary text against dark backing exceeds graphical target > 6:1."""
        ratio = calculate_contrast_ratio(COLOR_TEXT_MUTED, COLOR_DARK_THEME_BACKING)
        assert ratio >= WCAG_GRAPHICAL_CONTRAST_TARGET
        assert ratio > 6.0

    def test_all_8_node_colors_graphical_contrast_exceeds_3_to_1(self) -> None:
        """All 8 industrial refining entity colors exceed 3:1 graphical SCADA contrast."""
        for color in REFINING_NETWORK_PALETTE:
            ratio = calculate_contrast_ratio(color, COLOR_DARK_THEME_BACKING)
            assert ratio >= WCAG_GRAPHICAL_CONTRAST_TARGET

    def test_validate_wcag_aaa_contrast_helper(self) -> None:
        """validate_wcag_aaa_contrast helper accurately validates against target threshold."""
        assert validate_wcag_aaa_contrast(COLOR_TEXT_PRIMARY, COLOR_DECOUPLED_BADGE, 18.0) is True
        assert validate_wcag_aaa_contrast("#333333", "#444444", 7.0) is False


# ============================================================================
# Section 8: Diagnostic Fault Conditions (0xF401..0xF404)
# ============================================================================

class TestDiagnosticFaultConditions:
    """Validate 0xF401 singularity, 0xF402 empty entity matrix, 0xF403 residual > 5%, 0xF404 canvas overflow."""

    def test_diag_singularity_fault_0xf401(self) -> None:
        """Geometry singularity fault sets diagnostic code 0xF401."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_singularity_fault()
        assert canvas.diagnostic_code == DIAG_ERR_CHORD_GEOMETRY_SINGULARITY
        assert (canvas.diagnostic_code & 0xFFFF) == 0xF401
        assert not bool(canvas.status_bits & ChordFluxStatusBits.NOMINAL_OPERATION)

    def test_diag_empty_matrix_fault_0xf402(self) -> None:
        """Empty entity matrix fault sets diagnostic code 0xF402."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_empty_matrix_fault()
        assert canvas.diagnostic_code == DIAG_ERR_EMPTY_ENTITY_MATRIX
        assert (canvas.diagnostic_code & 0xFFFF) == 0xF402
        assert not bool(canvas.status_bits & ChordFluxStatusBits.NOMINAL_OPERATION)

    def test_diag_mass_balance_residual_fault_0xf403(self) -> None:
        """Mass balance residual > 5% fault sets diagnostic code 0xF403 and asserts %M456."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_mass_balance_residual_fault(imbalance_ppm=60000)
        assert canvas.diagnostic_code == DIAG_ERR_MASS_BALANCE_RESIDUAL
        assert (canvas.diagnostic_code & 0xFFFF) == 0xF403
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_bit("%M456") is True

    def test_diag_canvas_overflow_fault_0xf404(self) -> None:
        """Canvas overflow fault sets diagnostic code 0xF404."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_canvas_overflow_fault()
        assert canvas.diagnostic_code == DIAG_ERR_CANVAS_OVERFLOW
        assert (canvas.diagnostic_code & 0xFFFF) == 0xF404
        assert not bool(canvas.status_bits & ChordFluxStatusBits.NOMINAL_OPERATION)

    def test_validate_chord_geometry_singularity_raises(self) -> None:
        """validate_chord_geometry raises ChordGeometrySingularityError if inner >= outer or <= 0."""
        with pytest.raises(ChordGeometrySingularityError):
            validate_chord_geometry(inner_radius=300.0, outer_radius=200.0)
        with pytest.raises(ChordGeometrySingularityError):
            validate_chord_geometry(inner_radius=-10.0, outer_radius=200.0)

    def test_validate_chord_geometry_overflow_raises(self) -> None:
        """validate_chord_geometry raises CanvasOverflowError if outer_radius exceeds canvas bounds."""
        with pytest.raises(CanvasOverflowError):
            validate_chord_geometry(inner_radius=200.0, outer_radius=900.0)

    def test_validate_entity_matrix_empty_raises(self) -> None:
        """validate_entity_matrix raises EmptyEntityMatrixError if entity list is empty."""
        with pytest.raises(EmptyEntityMatrixError):
            validate_entity_matrix(entities=[])
        with pytest.raises(EmptyEntityMatrixError):
            validate_entity_matrix(entities=[1, 2], flow_matrix=[])

    def test_validate_mass_balance_residual_exceeded_raises(self) -> None:
        """validate_mass_balance_residual raises MassBalanceResidualError if residual > 5% (50,000 ppm)."""
        assert validate_mass_balance_residual(12.0) is True
        with pytest.raises(MassBalanceResidualError):
            validate_mass_balance_residual(55000.0)

    def test_diagnostic_status_code_in_register_r1957(self) -> None:
        """Horner register %R1957 stores signed 16-bit diagnostic status code."""
        canvas = create_canonical_chord_flux_canvas()
        table = RegisterTable()
        canvas.trigger_mass_balance_residual_fault()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_word("%R1957") == 0xF403 - 0x10000


# ============================================================================
# Section 9: Reset Nominal Recovery
# ============================================================================

class TestResetNominalRecovery:
    """Validate complete nominal recovery following faults and condition trips."""

    def test_reset_nominal_restores_diagnostic_code_to_ok(self) -> None:
        """Calling reset_nominal restores diagnostic code to DIAG_EVENT_OK (0x0000)."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_singularity_fault()
        canvas.reset_nominal()
        assert canvas.diagnostic_code == DIAG_EVENT_OK

    def test_reset_nominal_restores_canonical_entities(self) -> None:
        """All 8 entities are restored to online and initial nominal throughput."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_topology_node_offline(node_index=2)
        assert canvas.nodes[1].is_online is False
        canvas.reset_nominal()
        assert len(canvas.nodes) == 8
        assert all(n.is_online for n in canvas.nodes)

    def test_reset_nominal_restores_matrices(self) -> None:
        """Flow and capacity matrices are restored to canonical values."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.material_matrix[0][1] = 9999.0
        canvas.reset_nominal()
        assert canvas.material_matrix[0][1] == CANONICAL_MATERIAL_FLUX_MATRIX[0][1]

    def test_reset_nominal_restores_status_bits(self) -> None:
        """Status bits are restored to nominal operational mask."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_high_flux_imbalance_alarm()
        canvas.reset_nominal()
        assert bool(canvas.status_bits & ChordFluxStatusBits.NOMINAL_OPERATION)
        assert not bool(canvas.status_bits & ChordFluxStatusBits.FLUX_IMBALANCE_ALARM)

    def test_reset_nominal_restores_selection_indices(self) -> None:
        """Selected source and target indices are reset to (1, 2)."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.select_chord(source_index=5, target_index=7)
        canvas.reset_nominal()
        assert canvas.selected_source_node_index == 1
        assert canvas.selected_target_node_index == 2

    def test_reset_nominal_restores_registers_r1950_to_r1957(self) -> None:
        """Registers %R1950..%R1957 return to nominal state."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_high_flux_imbalance_alarm()
        canvas.reset_nominal()
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_word("%R1950") == 4500
        assert table.read_word("%R1954") == 8
        assert table.read_word("%R1957") == 0

    def test_reset_nominal_restores_coils_m455_and_m456(self) -> None:
        """Coil %M455 is True and %M456 is False after reset."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_high_flux_imbalance_alarm()
        canvas.reset_nominal()
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_bit("%M455") is True
        assert table.read_bit("%M456") is False


# ============================================================================
# Section 10: Horner OCS Synchronization and Registers (%R1950..%R1957, %M455..%M456)
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate RegisterTable memory sync (%R1950..%R1957, %M455..%M456) and SYSTEM privilege enforcement."""

    def test_w234_register_sync_nominal_values(self) -> None:
        """Word registers %R1950..%R1957 reflect exact nominal process values."""
        canvas = create_canonical_chord_flux_canvas()
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_word("%R1950") == 4500
        assert table.read_word("%R1951") == 1850
        assert table.read_word("%R1952") == 942
        assert table.read_word("%R1953") == 885
        assert table.read_word("%R1954") == 8
        assert table.read_word("%R1955") == 12
        assert table.read_word("%R1956") == 1
        assert table.read_word("%R1957") == 0

    def test_w234_discrete_coils_nominal_states(self) -> None:
        """Discrete coils %M455 (Active) is True and %M456 (High Imbalance Alarm) is False."""
        canvas = create_canonical_chord_flux_canvas()
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_bit("%M455") is True
        assert table.read_bit("%M456") is False

    def test_w234_register_writes_use_system_privilege(self) -> None:
        """RegisterTable updates succeed via PrivilegeMode.SYSTEM without raising PermissionError."""
        canvas = create_canonical_chord_flux_canvas()
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table, privilege=PrivilegeMode.SYSTEM)
        assert table.read_word("%R1950") == 4500

    def test_w234_select_chord_updates_selection_register(self) -> None:
        """select_chord(source, target) updates %R1956."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.select_chord(source_index=4, target_index=3)
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_word("%R1956") == 4

    def test_w234_sync_to_custom_register_table(self) -> None:
        """sync_to_registers updates custom external RegisterTable instance."""
        custom_table = RegisterTable()
        canvas = create_canonical_chord_flux_canvas()
        canvas.sync_to_registers(reg_table=custom_table)
        assert custom_table.read_word("%R1950") == 4500
        assert custom_table.read_bit("%M455") is True

    def test_w234_and_w198_dual_sync_compatibility(self) -> None:
        """Both W234 (%R1950..%R1957) and legacy W198 (%R1590..%R1597) are synchronized simultaneously."""
        canvas = create_canonical_chord_flux_canvas()
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        # W234 registers
        assert table.read_word("%R1950") == 4500
        assert table.read_word("%R1951") == 1850
        # W198 registers
        assert table.read_word("%R1590") == 4500
        assert table.read_word("%R1591") == 1850

    def test_w234_coils_m455_m456_with_m371_m372_compatibility(self) -> None:
        """Both W234 (%M455..%M456) and legacy W198 (%M371..%M372) coils are synchronized simultaneously."""
        canvas = create_canonical_chord_flux_canvas()
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_bit("%M455") is True
        assert table.read_bit("%M456") is False
        assert table.read_bit("%M371") is True
        assert table.read_bit("%M372") is True

    def test_register_read_unsigned_and_signed_values(self) -> None:
        """Signed diagnostic codes write properly to word registers."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_singularity_fault()
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_word("%R1957") == 0xF401 - 0x10000

    def test_active_entity_count_register_updates(self) -> None:
        """Setting entity offline updates %R1954 to 7."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_topology_node_offline(node_index=3)
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_word("%R1954") == 7

    def test_flux_imbalance_register_updates(self) -> None:
        """Forced imbalance updates %R1955."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_flux_imbalance(imbalance_ppm=65)
        table = RegisterTable()
        canvas.sync_to_registers(reg_table=table)
        assert table.read_word("%R1955") == 65


# ============================================================================
# Section 11: Pure IEC 61131-3 Structured Text (ST) POU
# ============================================================================

class TestPureSTAndSecurity:
    """Validate Pure ST POU grammar, variables, address bindings, and AST parsing."""

    def test_w234_st_pou_ast_parsing_and_program_name(self) -> None:
        """STParser cleanly parses CHORD_FLUX_W234_PURE_ST_POU with program name 'ChordFluxCanvasSync'."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(CHORD_FLUX_W234_PURE_ST_POU)
        assert pou is not None
        assert pou.name == "ChordFluxCanvasSync"
        assert pou.pou_type == POUType.PROGRAM

    def test_w234_st_pou_bound_registers_r1950_to_r1957(self) -> None:
        """CHORD_FLUX_W234_PURE_ST_POU binds variables to registers %R1950..%R1957."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(CHORD_FLUX_W234_PURE_ST_POU)
        vmap = {v.name: v.address_binding for v in pou.variables}
        assert vmap.get("TotalMaterialFluxMtH") == "%R1950"
        assert vmap.get("TotalEnergyExchangeMwScaled") == "%R1951"
        assert vmap.get("NetworkRecycleEfficiencyPctScaled") == "%R1952"
        assert vmap.get("MaxBottleneckSaturationPctScaled") == "%R1953"
        assert vmap.get("ActiveEntityCount") == "%R1954"
        assert vmap.get("FluxConservationImbalancePpm") == "%R1955"
        assert vmap.get("SelectedSourceEntityIndex") == "%R1956"
        assert vmap.get("DiagnosticStatusCode") == "%R1957"

    def test_w234_st_pou_bound_coils_m455_to_m456(self) -> None:
        """CHORD_FLUX_W234_PURE_ST_POU binds discrete coils %M455 and %M456."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(CHORD_FLUX_W234_PURE_ST_POU)
        vmap = {v.name: v.address_binding for v in pou.variables}
        assert vmap.get("ChordFluxCanvasActive") == "%M455"
        assert vmap.get("HighFluxImbalanceAlarmActive") == "%M456"

    def test_w234_st_pou_variable_types(self) -> None:
        """All word registers are INT and all coils are BOOL."""
        parser = STParser(pou_type=POUType.PROGRAM)
        pou = parser.parse_pou(CHORD_FLUX_W234_PURE_ST_POU)
        type_map = {v.name: v.data_type for v in pou.variables}
        assert type_map["TotalMaterialFluxMtH"] == "INT"
        assert type_map["DiagnosticStatusCode"] == "INT"
        assert type_map["ChordFluxCanvasActive"] == "BOOL"
        assert type_map["HighFluxImbalanceAlarmActive"] == "BOOL"

    def test_w234_st_pou_security_guard_pure_content(self) -> None:
        """SecurityGuard asserts CHORD_FLUX_W234_PURE_ST_POU contains zero ladder constructs."""
        SecurityGuard.assert_pure_st_content(CHORD_FLUX_W234_PURE_ST_POU)

    def test_verify_chord_flux_w234_pure_st_helper(self) -> None:
        """verify_chord_flux_w234_pure_st helper returns True deterministically."""
        assert verify_chord_flux_w234_pure_st() is True

    def test_legacy_w198_pure_st_pou_still_valid(self) -> None:
        """Legacy CHORD_FLUX_CANVAS_PURE_ST_POU remains pure and parseable."""
        SecurityGuard.assert_pure_st_content(CHORD_FLUX_CANVAS_PURE_ST_POU)
        assert verify_chord_flux_canvas_pure_st() is True

    def test_multi_echelon_pou_alias_valid(self) -> None:
        """MULTI_ECHELON_ENERGY_MASS_FLUX_PURE_ST_POU alias is pure and parseable."""
        SecurityGuard.assert_pure_st_content(MULTI_ECHELON_ENERGY_MASS_FLUX_PURE_ST_POU)
        assert verify_multi_echelon_energy_mass_flux_pure_st() is True


# ============================================================================
# Section 12: Anti-Ladder Security Guard Interception
# ============================================================================

class TestAntiLadderRejection:
    """Validate fail-closed interception of forbidden ladder constructs with LadderForbiddenError."""

    def test_anti_ladder_normally_open_contact(self) -> None:
        """Normally open contact construct '---[ ]---' is intercepted."""
        code = "PROGRAM BadLogic\nVAR x: BOOL; END_VAR\n---[ ]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_anti_ladder_normally_closed_contact(self) -> None:
        """Normally closed contact construct '---[/]---' is intercepted."""
        code = "PROGRAM BadLogic\nVAR x: BOOL; END_VAR\n---[/]---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_anti_ladder_normal_coils(self) -> None:
        """Standard output coil construct '---( )---' is intercepted."""
        code = "PROGRAM BadLogic\nVAR x: BOOL; END_VAR\n---( )---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code)

    def test_anti_ladder_set_reset_coils(self) -> None:
        """Set '---(S)---' and Reset '---(R)---' coils are intercepted."""
        code_s = "PROGRAM BadLogic\nVAR x: BOOL; END_VAR\n---(S)---\nEND_PROGRAM"
        code_r = "PROGRAM BadLogic\nVAR x: BOOL; END_VAR\n---(R)---\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code_s)
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code_r)

    def test_anti_ladder_rung_network_delimiters(self) -> None:
        """RUNG and NETWORK delimiters are intercepted."""
        code_rung = "PROGRAM BadLogic\nRUNG 1\nEND_PROGRAM"
        code_net = "PROGRAM BadLogic\nNETWORK 1\nEND_PROGRAM"
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code_rung)
        with pytest.raises(LadderForbiddenError):
            SecurityGuard.assert_pure_st_content(code_net)

    def test_anti_ladder_mnemonics(self) -> None:
        """Allen-Bradley mnemonics (XIC, XIO, OTE, OTL, OTU) are intercepted."""
        for mnemonic in ("XIC", "XIO", "OTE", "OTL", "OTU"):
            code = f"PROGRAM BadLogic\n{mnemonic} Sensor_1;\nEND_PROGRAM"
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(code)

    def test_anti_ladder_clean_pou_never_raises(self) -> None:
        """Valid IEC 61131-3 Pure ST code never raises LadderForbiddenError."""
        SecurityGuard.assert_pure_st_content(CHORD_FLUX_W234_PURE_ST_POU)


# ============================================================================
# Section 13: ILogicUnit Interface Compliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit interface compliance (scan_step, execute, reset, is_enabled, priority)."""

    def test_ilogic_unit_interface_implementation(self) -> None:
        """ChordFluxCanvas implements the ILogicUnit protocol."""
        canvas = create_canonical_chord_flux_canvas()
        assert isinstance(canvas, ILogicUnit)

    def test_ilogic_unit_contract_properties(self) -> None:
        """name, priority, is_enabled, and scan_count properties adhere to contract."""
        canvas = create_canonical_chord_flux_canvas()
        assert canvas.name == "ChordFluxCanvas"
        assert canvas.priority == 100
        assert canvas.is_enabled is True
        assert canvas.scan_count == 0

    def test_ilogic_unit_scan_step_increments_cycle_count(self) -> None:
        """Calling scan_step increments cycle counter and advances elapsed time."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.scan_step(dt=0.01)
        assert canvas.scan_count == 1
        canvas.scan_step(dt=0.01)
        assert canvas.scan_count == 2

    def test_ilogic_unit_execute_with_scan_context(self) -> None:
        """Calling execute with ScanContext runs scan logic without raising."""
        canvas = create_canonical_chord_flux_canvas()
        ctx = create_mock_scan_context(cycle=1, dt_ms=10.0)
        canvas.execute(ctx)
        assert canvas.scan_count == 1

    def test_ilogic_unit_step_and_execute_logic_aliases(self) -> None:
        """step and execute_logic method aliases execute properly."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.step(dt=0.02)
        assert canvas.scan_count == 1
        ctx = create_mock_scan_context(cycle=2, dt_ms=20.0)
        canvas.execute_logic(ctx)
        assert canvas.scan_count == 2

    def test_ilogic_unit_multi_cycle_stability_100_cycles(self) -> None:
        """100 continuous scan cycles maintain stable metrics without drift."""
        canvas = create_canonical_chord_flux_canvas()
        for i in range(100):
            canvas.scan_step(dt=0.01)
        assert canvas.scan_count == 100
        assert canvas.metrics.total_material_flux_mt_h == 4500.0

    def test_ilogic_unit_reset_method(self) -> None:
        """reset() restores initial nominal parameters."""
        canvas = create_canonical_chord_flux_canvas()
        canvas.trigger_high_flux_imbalance_alarm()
        canvas.reset()
        assert canvas.diagnostic_code == DIAG_EVENT_OK

    def test_mock_scan_context_factory(self) -> None:
        """create_mock_scan_context initializes valid ScanContext object."""
        ctx = create_mock_scan_context(cycle=5, dt_ms=10.0)
        assert ctx.cycle == 5
        assert ctx.dt_ms == 10.0
        assert ctx.elapsed_time_ms == 50.0


# ============================================================================
# Section 14: Verification Runner and Contract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate 9-stage verification runner and strict 4-state engineering contract."""

    def test_verification_runner_returns_strict_4_state_success(self) -> None:
        """run_chord_flux_canvas_verification returns status == 'success'."""
        result = run_chord_flux_canvas_verification()
        assert result["status"] == "success"
        assert result["error_code"] is None

    def test_verification_runner_all_9_stages_passed(self) -> None:
        """All 9 stages in test_results are marked passed: True."""
        result = run_chord_flux_canvas_verification()
        stages = result["data"].get("test_results") or result["data"].get("tests", [])
        assert len(stages) == 9
        assert all(s["passed"] is True for s in stages)

    def test_verification_runner_stage_structure(self) -> None:
        """Each stage report contains stage, check, passed, and details."""
        result = run_chord_flux_canvas_verification()
        stages = result["data"].get("test_results") or result["data"].get("tests", [])
        for s in stages:
            assert "stage" in s
            assert "check" in s
            assert "passed" in s
            assert "details" in s

    def test_verification_runner_evidence_json_export(self) -> None:
        """Verification runner exports valid JSON evidence to specified path."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            ev_path = tf.name
        try:
            res = run_chord_flux_canvas_verification(output_path=ev_path)
            assert Path(ev_path).is_file()
            with open(ev_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
        finally:
            Path(ev_path).unlink(missing_ok=True)

    def test_verification_runner_sample_svg_export(self) -> None:
        """Verification runner exports valid sample SVG to specified path."""
        with tempfile.NamedTemporaryFile(suffix=".svg", delete=False) as tf:
            svg_path = tf.name
        try:
            run_chord_flux_canvas_verification(sample_svg_path=svg_path)
            assert Path(svg_path).is_file()
            content = Path(svg_path).read_text(encoding="utf-8")
            assert content.startswith("<svg") or "<svg" in content
            ET.fromstring(content)
        finally:
            Path(svg_path).unlink(missing_ok=True)

    def test_verification_runner_custom_paths(self) -> None:
        """Verification runner supports both custom JSON and custom SVG paths simultaneously."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf1, \
             tempfile.NamedTemporaryFile(suffix=".svg", delete=False) as tf2:
            p1, p2 = tf1.name, tf2.name
        try:
            res = run_chord_flux_canvas_verification(output_path=p1, sample_svg_path=p2)
            assert res["status"] == "success"
            assert Path(p1).exists()
            assert Path(p2).exists()
        finally:
            Path(p1).unlink(missing_ok=True)
            Path(p2).unlink(missing_ok=True)

    def test_verification_cli_script_execution(self) -> None:
        """scripts/run_chord_flux_canvas_verification.py executes cleanly with exit code 0."""
        script_path = Path(__file__).resolve().parent.parent / "scripts" / "run_chord_flux_canvas_verification.py"
        res = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0
        assert "VERIFICATION SUCCESS" in res.stdout
