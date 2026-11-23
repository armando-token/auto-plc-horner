"""Comprehensive Unit and Integration Test Suite for Wave W242:
Industrial Maleic Anhydride Benzene/n-Butane Fixed-Bed Partial Oxidation ODE Simulation.

Work Package: W242 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: RIGOROUS_QA_TESTS (100+ Deterministic Assertions across 16 Test Classes)
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import tempfile
import time
import tracemalloc
from typing import Any, Dict, List

import pytest

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import POUType, STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.engine import ILogicUnit, ScanContext
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.maleic_anhydride_oxidation import (
    BED_TEMP_NOMINAL_C,
    BUTANE_CONVERSION_NOMINAL_PCT,
    BUTANE_CONV_NOMINAL_PCT,
    BUTANE_EXPLOSIVE_LIMIT_PCT,
    BUTANE_FEED_VOL_NOMINAL_PCT,
    COIL_EMERGENCY_TRIP_ACTIVE,
    COIL_HOTSPOT_PREALARM,
    COIL_OXIDATION_ACTIVE,
    COIL_OXIDATION_REACTOR_RUNNING,
    COIL_PREALARM_ACTIVE,
    COIL_REACTOR_EMERGENCY_TRIP,
    DELTA_H1_J_MOL,
    DELTA_H1_KJ_MOL,
    DELTA_H2_J_MOL,
    DELTA_H2_KJ_MOL,
    DELTA_H_COMBUSTION_J_MOL,
    DELTA_H_COMBUSTION_KJ_MOL,
    DELTA_H_MAN_J_MOL,
    DELTA_H_MAN_KJ_MOL,
    DiagnosticCode,
    FEED_CONC_MAX_EXPLOSIVE_PCT,
    FEED_CONC_NOMINAL_PCT,
    HOTSPOT_TEMP_NOMINAL_C,
    HYDROCARBON_CONV_NOMINAL_PCT,
    INLET_PRESSURE_NOMINAL_BAR,
    MALEIC_ANHYDRIDE_OXIDATION_PURE_ST_POU,
    MALEIC_ANHYDRIDE_OXIDATION_SYNC_POU,
    MALEIC_OXIDATION_PURE_ST_POU,
    MALEIC_OXIDATION_SYNC_POU,
    MAN_PRODUCTION_RATE_NOMINAL_KG_H,
    MAN_SELECTIVITY_MIN_PCT,
    MAN_SELECTIVITY_NOMINAL_PCT,
    MAN_SELECT_NOMINAL_PCT,
    MW_BUTANE,
    MW_C,
    MW_C4H10,
    MW_C4H2O3,
    MW_CO,
    MW_CO2,
    MW_COX_AVG,
    MW_H,
    MW_H2O,
    MW_MALEIC_ANHYDRIDE,
    MW_MAN,
    MW_N,
    MW_N2,
    MW_O,
    MW_O2,
    MaleicAnhydrideDiagCode,
    MaleicAnhydrideDiagnosticCode,
    MaleicAnhydrideOxidation,
    MaleicAnhydrideOxidationConfig,
    MaleicAnhydrideOxidationDiagCode,
    MaleicAnhydrideOxidationDiagnosticCode,
    MaleicAnhydrideOxidationEngine,
    MaleicAnhydrideOxidationLogicUnit,
    MaleicAnhydrideOxidationModel,
    MaleicAnhydrideOxidationParameters,
    MaleicAnhydrideOxidationPlantModel,
    MaleicAnhydrideOxidationReactor,
    MaleicAnhydrideOxidationSimulationEngine,
    MaleicAnhydrideOxidationSimulator,
    MaleicAnhydrideOxidationState,
    MaleicAnhydrideOxidationStateAlias,
    MaleicAnhydrideOxidationStatusBits,
    MaleicAnhydrideOxidationStatusWord,
    MaleicDiagCode,
    MaleicDiagnosticCode,
    MaleicOxidation,
    MaleicOxidationConfig,
    MaleicOxidationDiagCode,
    MaleicOxidationDiagnosticCode,
    MaleicOxidationEngine,
    MaleicOxidationLogicUnit,
    MaleicOxidationModel,
    MaleicOxidationParameters,
    MaleicOxidationReactor,
    MaleicOxidationSimulator,
    MaleicOxidationState,
    MaleicOxidationStatusBits,
    MaleicOxidationStatusWord,
    O2_CONCENTRATION_NOMINAL_PCT,
    O2_EXPLOSIVE_THRESHOLD_PCT,
    OXYGEN_CONC_NOMINAL_PCT,
    P_INLET_NOMINAL_BAR,
    PRODUCTION_RATE_NOMINAL_KG_H,
    PureSTValidationResult,
    REG_BED_HOTSPOT_TEMP_SCALED,
    REG_BUTANE_CONVERSION_SCALED,
    REG_DIAGNOSTIC_CODE,
    REG_FEED_CONCENTRATION_SCALED,
    REG_HYDROCARBON_CONVERSION_SCALED,
    REG_INLET_PRESSURE_SCALED,
    REG_MAN_PRODUCTION_RATE_KG_H,
    REG_MAN_SELECTIVITY_SCALED,
    REG_MOLTEN_SALT_TEMP_SCALED,
    REG_OXYGEN_CONCENTRATION_SCALED,
    REG_PRODUCTION_RATE_KG_H,
    REG_REACTOR_HOTSPOT_TEMP_SCALED,
    REG_SALT_COOLANT_TEMP_SCALED,
    R_GAS_CONST,
    SALT_COOLANT_TEMP_NOMINAL_C,
    StatusBits,
    T_BED_HOTSPOT_PREALARM_C,
    T_BED_NOMINAL_C,
    T_BED_RUNAWAY_TRIP_C,
    T_HOTSPOT_NOMINAL_C,
    T_HOTSPOT_PREALARM_C,
    T_HOTSPOT_RUNAWAY_C,
    T_NOMINAL_C,
    T_NOMINAL_K,
    T_REF_K,
    T_SALT_MAX_C,
    T_SALT_NOMINAL_C,
    T_ZERO_CELSIUS,
    run_maleic_anhydride_oxidation_verification,
    run_maleic_oxidation_verification,
    verify_maleic_anhydride_oxidation_pure_st,
    verify_maleic_oxidation_pure_st,
)


# ============================================================================
# 1. TestConstantsEnumsAndDiagnostics
# ============================================================================

class TestConstantsEnumsAndDiagnostics:
    """Validate register bindings, diagnostic codes, enum representations, and status bits."""

    def test_diagnostic_codes_values(self) -> None:
        assert DiagnosticCode.REACTOR_OK == 0x0000
        assert DiagnosticCode.THERMAL_HOTSPOT_RUNAWAY == 0xF101
        assert DiagnosticCode.EXPLOSIVE_LIMIT_VIOLATION == 0xF102
        assert DiagnosticCode.MOLTEN_SALT_CIRCULATION_LOSS == 0xF103
        assert DiagnosticCode.VPO_CATALYST_SELECTIVITY_COLLAPSE == 0xF104

    def test_diagnostic_code_signed_equality(self) -> None:
        # Signed 16-bit representation: 0xF101 - 0x10000 = -3839
        assert DiagnosticCode.THERMAL_HOTSPOT_RUNAWAY == -3839
        assert DiagnosticCode.EXPLOSIVE_LIMIT_VIOLATION == -3838
        assert DiagnosticCode.MOLTEN_SALT_CIRCULATION_LOSS == -3837
        assert DiagnosticCode.VPO_CATALYST_SELECTIVITY_COLLAPSE == -3836
        assert DiagnosticCode.REACTOR_OK == 0

    def test_diagnostic_code_missing_lookup(self) -> None:
        assert DiagnosticCode(-3839) == DiagnosticCode.THERMAL_HOTSPOT_RUNAWAY
        assert DiagnosticCode(-3838) == DiagnosticCode.EXPLOSIVE_LIMIT_VIOLATION
        assert DiagnosticCode(0xF101) == DiagnosticCode.THERMAL_HOTSPOT_RUNAWAY
        assert DiagnosticCode(0x0000) == DiagnosticCode.REACTOR_OK

    def test_diagnostic_code_bitwise_and(self) -> None:
        assert (DiagnosticCode.THERMAL_HOTSPOT_RUNAWAY & 0xFFFF) == 0xF101
        assert (0xFFFF & DiagnosticCode.THERMAL_HOTSPOT_RUNAWAY) == 0xF101
        assert hash(DiagnosticCode.THERMAL_HOTSPOT_RUNAWAY) == hash(0xF101)

    def test_status_bits_definitions(self) -> None:
        assert MaleicOxidationStatusBits.RUNNING == 0x0001
        assert MaleicOxidationStatusBits.REACTOR_RUNNING == 0x0002
        assert MaleicOxidationStatusBits.HOTSPOT_PREALARM == 0x0004
        assert MaleicOxidationStatusBits.REACTOR_EMERGENCY_TRIP == 0x0008
        assert MaleicOxidationStatusBits.HOTSPOT_RUNAWAY_FAULT == 0x0010
        assert MaleicOxidationStatusBits.EXPLOSIVE_LIMIT_FAULT == 0x0020
        assert MaleicOxidationStatusBits.SALT_CIRCULATION_FAULT == 0x0040
        assert MaleicOxidationStatusBits.SELECTIVITY_COLLAPSE_FAULT == 0x0080

    def test_register_and_coil_constants(self) -> None:
        assert REG_REACTOR_HOTSPOT_TEMP_SCALED == "%R2030"
        assert REG_BUTANE_CONVERSION_SCALED == "%R2031"
        assert REG_MAN_SELECTIVITY_SCALED == "%R2032"
        assert REG_SALT_COOLANT_TEMP_SCALED == "%R2033"
        assert REG_OXYGEN_CONCENTRATION_SCALED == "%R2034"
        assert REG_INLET_PRESSURE_SCALED == "%R2035"
        assert REG_MAN_PRODUCTION_RATE_KG_H == "%R2036"
        assert REG_DIAGNOSTIC_CODE == "%R2037"
        assert COIL_OXIDATION_REACTOR_RUNNING == "%M473"
        assert COIL_HOTSPOT_PREALARM == "%M474"
        assert COIL_REACTOR_EMERGENCY_TRIP == "%M475"

    def test_aliases_consistency(self) -> None:
        assert MaleicOxidationDiagnosticCode is DiagnosticCode
        assert MaleicAnhydrideDiagnosticCode is DiagnosticCode
        assert MaleicDiagCode is DiagnosticCode
        assert MaleicOxidationStatusWord is MaleicOxidationStatusBits
        assert StatusBits is MaleicOxidationStatusBits


# ============================================================================
# 2. TestMaleicOxidationPhysicsAndKinetics
# ============================================================================

class TestMaleicOxidationPhysicsAndKinetics:
    """Validate chemical stoichiometry, thermochemical enthalpies, and Arrhenius kinetics."""

    def test_universal_physical_constants(self) -> None:
        assert abs(R_GAS_CONST - 8.314462618) < 1e-6
        assert T_ZERO_CELSIUS == 273.15
        assert T_REF_K == 683.15

    def test_molecular_weights(self) -> None:
        # C4H10: 4 * 12.011 + 10 * 1.008 = 58.124 g/mol
        assert abs(MW_BUTANE - 0.058124) < 1e-6
        # O2: 2 * 15.999 = 31.998 g/mol
        assert abs(MW_O2 - 0.031998) < 1e-6
        # C4H2O3: 4 * 12.011 + 2 * 1.008 + 3 * 15.999 = 98.057 g/mol
        assert abs(MW_MAN - 0.098057) < 1e-6
        # H2O: 2 * 1.008 + 15.999 = 18.015 g/mol
        assert abs(MW_H2O - 0.018015) < 1e-6

    def test_reaction_stoichiometry_mass_conservation(self) -> None:
        # Reaction 1: C4H10 + 3.5 O2 -> C4H2O3 + 4 H2O
        mass_reactants_1 = MW_BUTANE + 3.5 * MW_O2
        mass_products_1 = MW_MAN + 4.0 * MW_H2O
        assert abs(mass_reactants_1 - mass_products_1) < 1e-12

        # Reaction 2: C4H10 + 5.5 O2 -> 2 CO + 2 CO2 + 5 H2O
        mass_reactants_2 = MW_BUTANE + 5.5 * MW_O2
        mass_products_2 = 2.0 * MW_CO + 2.0 * MW_CO2 + 5.0 * MW_H2O
        assert abs(mass_reactants_2 - mass_products_2) < 1e-12

    def test_reaction_enthalpies(self) -> None:
        assert DELTA_H1_KJ_MOL == -1260.0
        assert DELTA_H1_J_MOL == -1260000.0
        assert DELTA_H2_KJ_MOL == -2870.0
        assert DELTA_H2_J_MOL == -2870000.0
        assert DELTA_H_MAN_KJ_MOL == -1260.0
        assert DELTA_H_COMBUSTION_KJ_MOL == -2870.0

    def test_arrhenius_kinetics_temperature_monotonicity(self) -> None:
        sim = MaleicAnhydrideOxidation()
        t_low = 380.0 + T_ZERO_CELSIUS
        t_mid = 410.0 + T_ZERO_CELSIUS
        t_high = 440.0 + T_ZERO_CELSIUS

        k1_low = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_low)
        k1_mid = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_mid)
        k1_high = sim.arrhenius_rate_constant(sim.config.arrhenius_a1, sim.config.activation_e1_j_mol, t_high)

        assert k1_high > k1_mid > k1_low > 0.0

        # Verify activation energy recovery via Arrhenius slope
        recovered_ea1 = -R_GAS_CONST * math.log(k1_high / k1_low) / ((1.0 / t_high) - (1.0 / t_low))
        assert abs(recovered_ea1 - sim.config.activation_e1_j_mol) < 1e-3


# ============================================================================
# 3. TestRK4NumericalSolver
# ============================================================================

class TestRK4NumericalSolver:
    """Validate 6-state ODE derivative formulation and Runge-Kutta 4th order solver."""

    def test_compute_derivatives_structure(self) -> None:
        sim = MaleicAnhydrideOxidation()
        y = [0.1234, 0.4844, 0.7535, 7.088, 410.0 + T_ZERO_CELSIUS, 385.0 + T_ZERO_CELSIUS]
        derivs = sim.compute_derivatives(0.0, y)
        assert len(derivs) == 6
        assert all(not math.isnan(d) for d in derivs)

    def test_rk4_step_integration(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        t_start = sim.state.sim_time_s
        sc_start = sim.state.scan_count

        sim.step(dt=0.02)
        assert abs(sim.state.sim_time_s - (t_start + 0.02)) < 1e-6
        assert sim.state.scan_count == sc_start + 1
        assert not math.isnan(sim.state.hotspot_temp_c)
        assert not math.isnan(sim.state.c_man)
        assert sim.state.c_man > 0.0

    def test_non_negativity_clamping(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        sim.state.c_butane = 0.0
        derivs = sim.compute_derivatives(0.0, [0.0, 0.0, 0.0, 0.0, 683.15, 658.15])
        # Inlet flow pushes butane rate positive
        assert derivs[0] > 0.0


# ============================================================================
# 4. TestNominalSteadyStateConvergence
# ============================================================================

class TestNominalSteadyStateConvergence:
    """Validate nominal operating regime convergence and baseline telemetry."""

    def test_nominal_steady_state_values(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()

        assert abs(sim.state.hotspot_temp_c - 410.0) < 0.1
        assert abs(sim.state.butane_conversion_pct - 84.50) < 0.1
        assert abs(sim.state.man_selectivity_pct - 72.00) < 0.1
        assert abs(sim.state.salt_coolant_temp_c - 385.0) < 0.1
        assert abs(sim.state.oxygen_concentration_pct - 18.50) < 0.1
        assert abs(sim.state.inlet_pressure_bar - 2.20) < 0.01
        assert abs(sim.state.man_production_rate_kg_h - 2850.0) < 10.0

    def test_nominal_coils_and_diagnostic(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()

        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK
        assert sim.state.oxidation_reactor_running is True
        assert sim.state.hotspot_prealarm is False
        assert sim.state.reactor_emergency_trip is False


# ============================================================================
# 5. TestConservationLawsAndThermodynamics
# ============================================================================

class TestConservationLawsAndThermodynamics:
    """Validate mathematical mass, elemental, and enthalpy conservation (< 1e-10)."""

    def test_mass_conservation_residual_less_than_1e10(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        sim._update_conservation_residuals()

        assert sim.state.total_mass_balance_residual_kg_s < 1.0e-10

    def test_elemental_conservation_residual_less_than_1e10(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        sim._update_conservation_residuals()

        assert sim.state.elemental_mass_balance_residual_kg_s < 1.0e-10

    def test_enthalpy_conservation_residual_less_than_1e10(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        sim._update_conservation_residuals()

        assert sim.state.enthalpy_conservation_residual_kw < 1.0e-10

    def test_heat_generation_and_removal_balance(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()

        assert sim.state.q_rxn_kw > 15000.0  # Significant exothermic release
        assert sim.state.q_cool_kw > 10000.0  # Molten salt cooling removes majority of heat
        assert sim.state.q_flow_kw > 3000.0   # Sensible gas sensible removal


# ============================================================================
# 6. TestThermalRunawayFault0xF101
# ============================================================================

class TestThermalRunawayFault0xF101:
    """Validate 0xF101 hotspot runaway trip and %M474 pre-alarm behavior."""

    def test_hotspot_prealarm_activation(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        sim.state.hotspot_temp_c = 445.0  # > 440 °C but < 470 °C
        sim._evaluate_safety_interlocks()

        assert sim.state.hotspot_prealarm is True
        assert sim.state.reactor_emergency_trip is False
        assert sim.state.oxidation_reactor_running is True
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK

    def test_hotspot_runaway_trip_activation(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        sim.state.hotspot_temp_c = 475.0  # > 470 °C
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_HOTSPOT_RUNAWAY
        assert sim.state.hotspot_prealarm is True
        assert sim.state.reactor_emergency_trip is True
        assert sim.state.oxidation_reactor_running is False
        assert MaleicOxidationStatusBits.HOTSPOT_RUNAWAY_FAULT in sim.state.status_bits


# ============================================================================
# 7. TestExplosiveLimitViolation0xF102
# ============================================================================

class TestExplosiveLimitViolation0xF102:
    """Validate 0xF102 explosive flammability limit trip."""

    def test_explosive_limit_trip(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        sim.state.butane_feed_vol_pct = 2.10       # > 1.8 vol%
        sim.state.oxygen_concentration_pct = 18.50  # > 15.0%
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.EXPLOSIVE_LIMIT_VIOLATION
        assert sim.state.reactor_emergency_trip is True
        assert sim.state.oxidation_reactor_running is False
        assert MaleicOxidationStatusBits.EXPLOSIVE_LIMIT_FAULT in sim.state.status_bits

    def test_low_oxygen_inert_margin_no_trip(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        sim.state.butane_feed_vol_pct = 2.10
        sim.state.oxygen_concentration_pct = 12.0  # Below 15.0% threshold
        sim._evaluate_safety_interlocks()

        # Should not trip 0xF102 when inerted below 15% O2
        assert sim.state.diagnostic_code != DiagnosticCode.EXPLOSIVE_LIMIT_VIOLATION


# ============================================================================
# 8. TestMoltenSaltCirculationLoss0xF103
# ============================================================================

class TestMoltenSaltCirculationLoss0xF103:
    """Validate 0xF103 molten salt coolant temperature excursion."""

    def test_molten_salt_loss_alert(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        sim.state.salt_coolant_temp_c = 435.0  # > 430 °C
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.MOLTEN_SALT_CIRCULATION_LOSS
        assert sim.state.reactor_emergency_trip is False
        assert sim.state.oxidation_reactor_running is True
        assert MaleicOxidationStatusBits.SALT_CIRCULATION_FAULT in sim.state.status_bits


# ============================================================================
# 9. TestVPOSelectivityCollapse0xF104
# ============================================================================

class TestVPOSelectivityCollapse0xF104:
    """Validate 0xF104 catalyst selectivity collapse alert."""

    def test_selectivity_collapse_alert(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        sim.state.man_selectivity_pct = 55.0  # < 60.0%
        sim._evaluate_safety_interlocks()

        assert sim.state.diagnostic_code == DiagnosticCode.VPO_CATALYST_SELECTIVITY_COLLAPSE
        assert sim.state.reactor_emergency_trip is False
        assert sim.state.oxidation_reactor_running is True
        assert MaleicOxidationStatusBits.SELECTIVITY_COLLAPSE_FAULT in sim.state.status_bits


# ============================================================================
# 10. TestProcessSafetyStrictPriorityHierarchy
# ============================================================================

class TestProcessSafetyStrictPriorityHierarchy:
    """Validate strict priority resolution among competing faults (P1 > P2 > P3 > P4 > P5)."""

    def test_priority_cascading(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()

        # Step 1: Trigger all 4 faults simultaneously -> Priority 1 (0xF101) must win
        sim.state.hotspot_temp_c = 475.0               # Priority 1: 0xF101
        sim.state.butane_feed_vol_pct = 2.10           # Priority 2: 0xF102
        sim.state.oxygen_concentration_pct = 18.50
        sim.state.salt_coolant_temp_c = 435.0          # Priority 3: 0xF103
        sim.state.man_selectivity_pct = 55.0           # Priority 4: 0xF104
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.THERMAL_HOTSPOT_RUNAWAY

        # Step 2: Clear Priority 1 -> Priority 2 (0xF102) must win
        sim.state.hotspot_temp_c = 410.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.EXPLOSIVE_LIMIT_VIOLATION

        # Step 3: Clear Priority 2 -> Priority 3 (0xF103) must win
        sim.state.butane_feed_vol_pct = 1.50
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.MOLTEN_SALT_CIRCULATION_LOSS

        # Step 4: Clear Priority 3 -> Priority 4 (0xF104) must win
        sim.state.salt_coolant_temp_c = 385.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.VPO_CATALYST_SELECTIVITY_COLLAPSE

        # Step 5: Clear Priority 4 -> Priority 5 (0x0000) must win
        sim.state.man_selectivity_pct = 72.0
        sim._evaluate_safety_interlocks()
        assert sim.state.diagnostic_code == DiagnosticCode.REACTOR_OK


# ============================================================================
# 11. TestHornerOCSSynchronizationAndRegisters
# ============================================================================

class TestHornerOCSSynchronizationAndRegisters:
    """Validate bit-exact Horner OCS memory map (%R2030..%R2037, %M473..%M475)."""

    def test_sync_to_registers_nominal(self) -> None:
        table = RegisterTable()
        sim = MaleicAnhydrideOxidation(register_table=table)
        sim.reset()

        assert table.read_word("%R2030") == 4100
        assert table.read_word("%R2031") == 8450
        assert table.read_word("%R2032") == 7200
        assert table.read_word("%R2033") == 3850
        assert table.read_word("%R2034") == 1850
        assert table.read_word("%R2035") == 220
        assert table.read_word("%R2036") == 2850
        assert table.read_uword("%R2037") == 0x0000
        assert table.read_bit("%M473") is True
        assert table.read_bit("%M474") is False
        assert table.read_bit("%M475") is False

    def test_sync_to_registers_fault_trip(self) -> None:
        table = RegisterTable()
        sim = MaleicAnhydrideOxidation(register_table=table)
        sim.reset()
        sim.state.hotspot_temp_c = 475.0
        sim._evaluate_safety_interlocks()
        sim._sync_registers()

        assert table.read_word("%R2030") == 4750
        assert table.read_uword("%R2037") == 0xF101
        assert table.read_word("%R2037") == -3839  # Signed representation
        assert table.read_bit("%M473") is False
        assert table.read_bit("%M474") is True
        assert table.read_bit("%M475") is True


# ============================================================================
# 12. TestPureSTAndSecurity
# ============================================================================

class TestPureSTAndSecurity:
    """Validate pure IEC 61131-3 Structured Text POU and AST parsing."""

    def test_pure_st_security_guard(self) -> None:
        SecurityGuard.assert_pure_st_content(MALEIC_ANHYDRIDE_OXIDATION_PURE_ST_POU)

    def test_st_parser_validation(self) -> None:
        val = STParser.validate_code(MALEIC_ANHYDRIDE_OXIDATION_PURE_ST_POU)
        assert val.status == AgentStatus.SUCCESS

    def test_st_pou_ast_bindings(self) -> None:
        parser = STParser(pou_type=POUType.PROGRAM)
        ast = parser.parse_pou(MALEIC_ANHYDRIDE_OXIDATION_PURE_ST_POU)
        assert ast is not None
        assert ast.name == "MaleicAnhydrideOxidationSync"
        assert ast.pou_type == POUType.PROGRAM

        expected_regs = [
            "%R2030", "%R2031", "%R2032", "%R2033",
            "%R2034", "%R2035", "%R2036", "%R2037",
            "%M473", "%M474", "%M475",
        ]
        for reg in expected_regs:
            assert reg in ast.bound_registers

    def test_verify_maleic_pure_st_function(self) -> None:
        res = verify_maleic_anhydride_oxidation_pure_st()
        assert bool(res) is True
        assert res.status == AgentStatus.SUCCESS


# ============================================================================
# 13. TestAntiLadderRejection
# ============================================================================

class TestAntiLadderRejection:
    """Validate strict rejection of ladder logic constructs (ERR_LADDER_FORBIDDEN)."""

    def test_rejection_contacts_and_coils(self) -> None:
        bad_samples = [
            "PROGRAM Bad ---[ ]--- END_PROGRAM",
            "PROGRAM Bad ---[/]--- END_PROGRAM",
            "PROGRAM Bad ---( )--- END_PROGRAM",
            "PROGRAM Bad ---(S)--- END_PROGRAM",
            "PROGRAM Bad RUNG 1 END_PROGRAM",
            "PROGRAM Bad XIC(Bit1) END_PROGRAM",
        ]
        for sample in bad_samples:
            with pytest.raises(LadderForbiddenError):
                SecurityGuard.assert_pure_st_content(sample)


# ============================================================================
# 14. TestILogicUnitCompliance
# ============================================================================

class TestILogicUnitCompliance:
    """Validate ILogicUnit protocol compliance and 100-cycle soak stability."""

    def test_ilogic_unit_properties(self) -> None:
        sim = MaleicAnhydrideOxidation()
        assert sim.name == "MaleicAnhydrideOxidationSync"
        assert sim.priority == 10
        assert sim.is_enabled is True
        sim.disable()
        assert sim.is_enabled is False
        sim.enable()
        assert sim.is_enabled is True

    def test_scan_step_and_execute(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        sim.execute(ctx)
        assert sim.state.scan_count == 1
        assert abs(sim.state.sim_time_s - 0.02) < 1e-6

    def test_100_cycle_soak_stability(self) -> None:
        sim = MaleicAnhydrideOxidation()
        sim.reset()

        tracemalloc.start()
        snap1 = tracemalloc.take_snapshot()
        for c in range(1, 101):
            ctx = ScanContext(cycle=c, dt_ms=20.0, elapsed_time_ms=c * 20.0, dt=0.02)
            sim.execute(ctx)
        snap2 = tracemalloc.take_snapshot()
        tracemalloc.stop()

        stats = snap2.compare_to(snap1, "lineno")
        mem_diff_kb = sum(s.size_diff for s in stats if s.size_diff > 0) / 1024.0

        assert not math.isnan(sim.state.hotspot_temp_c)
        assert not math.isnan(sim.state.c_man)
        assert 400.0 <= sim.state.hotspot_temp_c <= 420.0
        assert sim.state.butane_conversion_pct > 80.0
        assert sim.state.man_selectivity_pct > 70.0
        assert mem_diff_kb < 1000.0

    def test_logic_unit_adapter(self) -> None:
        unit = MaleicAnhydrideOxidationLogicUnit()
        assert unit.name == "MaleicAnhydrideOxidationSync"
        assert unit.is_enabled is True
        ctx = ScanContext(cycle=1, dt_ms=20.0, elapsed_time_ms=20.0, dt=0.02)
        unit.execute(ctx)
        assert unit.state.scan_count == 1


# ============================================================================
# 15. TestVerificationRunnerAndContract
# ============================================================================

class TestVerificationRunnerAndContract:
    """Validate 9-stage verification runner returning strict 4-state contract."""

    def test_verification_runner_success(self) -> None:
        res = run_maleic_anhydride_oxidation_verification(work_package="W242")
        assert res["status"] == "success"
        assert res["error_code"] is None
        assert res["data"]["checks_passed"] == 9
        assert res["data"]["total_checks"] == 9
        assert len(res["data"]["stages"]) == 9

    def test_verification_runner_file_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "w242_verification.json"
            res = run_maleic_anhydride_oxidation_verification(output_path=out_file)
            assert out_file.exists()
            with open(out_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            assert loaded["status"] == "success"
            assert loaded["data"]["checks_passed"] == 9


# ============================================================================
# 16. TestEdgeCasesAndConfigModels
# ============================================================================

class TestEdgeCasesAndConfigModels:
    """Validate custom configurations and state property edge cases."""

    def test_custom_config(self) -> None:
        cfg = MaleicAnhydrideOxidationConfig(nominal_hotspot_temp_c=415.0)
        sim = MaleicAnhydrideOxidation(config=cfg)
        assert sim.config.nominal_hotspot_temp_c == 415.0

    def test_state_temperature_properties(self) -> None:
        st = MaleicAnhydrideOxidationState()
        st.t_hotspot = 425.0
        assert st.hotspot_temp_c == 425.0
        assert st.t_hotspot == 425.0

        st.t_salt = 390.0
        assert st.salt_coolant_temp_c == 390.0
        assert st.t_salt == 390.0

    def test_state_conversion_properties(self) -> None:
        st = MaleicAnhydrideOxidationState()
        st.conversion_pct = 85.0
        assert st.butane_conversion_pct == 85.0
        assert st.conversion_pct == 85.0

        st.selectivity_pct = 73.0
        assert st.man_selectivity_pct == 73.0
        assert st.selectivity_pct == 73.0
