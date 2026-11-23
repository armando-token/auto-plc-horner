#!/usr/bin/env python3
"""Verification Runner for Industrial Catalytic PHA Hydrogenation & 1,4-Butanediol Precursor Fixed-Bed ODE Simulation (W317).

Work Package: W317 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Fixed-Bed Catalytic PHA Hydrogenation & 1,4-BDO Synthesis 9-Stage Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: environment_and_platform_check
  Stage 2: physical_constants_and_register_mappings
  Stage 3: catalytic_kinetics_and_selectivity
  Stage 4: continuous_rk4_solver_and_mass_conservation
  Stage 5: thermal_runaway_and_overpressure_trips
  Stage 6: catalyst_coking_and_h2_starvation_diagnostics
  Stage 7: register_table_synchronization_and_system_privilege
  Stage 8: pure_st_pou_and_anti_ladder_rejection
  Stage 9: continuous_soak_100_cycles_and_evidence_emission

Generates:
  artifacts/simulation/pha_hydrogenation_bdo_evidence.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional, Union

# Ensure repository root and src/ are on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from jev_cscape.contracts import AgentStatus, ExecutionResult
from jev_cscape.iec.st_parser import STParser
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable

from jev_cscape.simulation.pha_hydrogenation_bdo import (
    COIL_PHA_H2_EMERGENCY_DEPRESSURIZE,
    COIL_PHA_H2_HYDROGEN_FEED_VALVE,
    COIL_PHA_H2_REACTOR_ACTIVE,
    DIAG_ERR_CATALYST_COKING,
    DIAG_ERR_HYDROGEN_STARVATION,
    DIAG_ERR_MASS_BALANCE_DIVERGENCE,
    DIAG_ERR_OVERPRESSURE_RUPTURE,
    DIAG_ERR_THERMAL_RUNAWAY,
    DIAG_OK,
    MW_BDO,
    MW_CARBON,
    MW_GBL,
    MW_H2,
    MW_METHANOL,
    MW_SUCCINATE_ESTER,
    PHA_HYDROGENATION_BDO_PURE_ST_POU,
    REG_PHA_H2_BDO_SELECTIVITY,
    REG_PHA_H2_CATALYST_ACTIVITY,
    REG_PHA_H2_CONVERSION_EFFICIENCY,
    REG_PHA_H2_DIAGNOSTIC_CODE,
    REG_PHA_H2_HYDROGEN_FLOW_SLPM,
    REG_PHA_H2_REACTOR_PRESSURE,
    REG_PHA_H2_REACTOR_TEMP,
    REG_PHA_H2_SPACE_VELOCITY_LHSV,
    R_GAS_CONSTANT,
    T_ZERO_CELSIUS,
    DiagnosticCode,
    PHAHydrogenationBDOConfig,
    PHAHydrogenationBDOEngine,
    PHAHydrogenationBDOState,
    PHAHydrogenationBDOStatusWord,
    verify_pha_hydrogenation_bdo_pure_st,
)

# Optional aliases fallback
try:
    from jev_cscape.simulation.pha_hydrogenation_bdo import (
        COIL_PHA_H2_ACTIVE,
        COIL_PHA_H2_DEPRESSURIZE,
        COIL_PHA_H2_FEED,
        REG_PHA_H2_ACTIVITY,
        REG_PHA_H2_CONVERSION,
        REG_PHA_H2_DIAG,
        REG_PHA_H2_FLOW,
        REG_PHA_H2_LHSV,
        REG_PHA_H2_PRESSURE,
        REG_PHA_H2_SELECTIVITY,
        REG_PHA_H2_TEMP,
    )
except ImportError:
    COIL_PHA_H2_ACTIVE = COIL_PHA_H2_REACTOR_ACTIVE
    COIL_PHA_H2_FEED = COIL_PHA_H2_HYDROGEN_FEED_VALVE
    COIL_PHA_H2_DEPRESSURIZE = COIL_PHA_H2_EMERGENCY_DEPRESSURIZE
    REG_PHA_H2_TEMP = REG_PHA_H2_REACTOR_TEMP
    REG_PHA_H2_PRESSURE = REG_PHA_H2_REACTOR_PRESSURE
    REG_PHA_H2_CONVERSION = REG_PHA_H2_CONVERSION_EFFICIENCY
    REG_PHA_H2_SELECTIVITY = REG_PHA_H2_BDO_SELECTIVITY
    REG_PHA_H2_LHSV = REG_PHA_H2_SPACE_VELOCITY_LHSV
    REG_PHA_H2_ACTIVITY = REG_PHA_H2_CATALYST_ACTIVITY
    REG_PHA_H2_FLOW = REG_PHA_H2_HYDROGEN_FLOW_SLPM
    REG_PHA_H2_DIAG = REG_PHA_H2_DIAGNOSTIC_CODE

# ANSI terminal formatting constants matching repo conventions
ESC_RESET = "\033[0m"
ESC_BOLD = "\033[1m"
ESC_DIM = "\033[2m"
ESC_GREEN = "\033[92m"
ESC_RED = "\033[91m"
ESC_YELLOW = "\033[93m"
ESC_CYAN = "\033[96m"


def format_stage_result(
    stage: int | str,
    check: str,
    passed: bool,
    timing_ms: Optional[float] = None,
    details: str = "",
    status: Optional[str] = None,
) -> str:
    """Format single stage verification outcome for terminal display."""
    if status is not None:
        if status == "success":
            badge = f"{ESC_GREEN}[PASS]{ESC_RESET}"
        elif status == "blocked":
            badge = f"{ESC_YELLOW}[BLOCKED]{ESC_RESET}"
        else:
            badge = f"{ESC_RED}[FAIL]{ESC_RESET}"
    else:
        badge = f"{ESC_GREEN}[PASS]{ESC_RESET}" if passed else f"{ESC_RED}[FAIL]{ESC_RESET}"

    timing_str = f" ({timing_ms:.1f}ms)" if timing_ms is not None else ""
    line = f"  Stage {stage:>2}: {badge} {ESC_BOLD}{check}{ESC_RESET}{timing_str}"
    if details:
        line += f"\n            {ESC_DIM}{details}{ESC_RESET}"
    return line


def execute_pha_hydrogenation_bdo_verification(
    output_path: Optional[str] = None,
    work_package: str = "W317",
    quick: bool = False,
    project_root: Optional[Any] = None,
) -> Dict[str, Any]:
    """Execute the canonical 9-stage verification sequence for W317 PHA Hydrogenation & 1,4-BDO.

    Strictly conforms to the 4-state contract: success | failed | blocked | inconclusive.
    Only writes evidence to output_path if output_path is provided.
    """
    stages: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: environment_and_platform_check
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    py_ok = sys.version_info >= (3, 10)
    platform_ok = bool(sys.platform)
    try:
        import hashlib as _hl
        import json as _js
        import math as _m
        import pathlib as _pl
        from jev_cscape.contracts import AgentStatus, ExecutionResult
        from jev_cscape.iec.st_parser import STParser
        from jev_cscape.security.exceptions import LadderForbiddenError
        from jev_cscape.security.guard import SecurityGuard
        from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
        from jev_cscape.simulation.pha_hydrogenation_bdo import (
            PHAHydrogenationBDOConfig,
            PHAHydrogenationBDOEngine,
            PHAHydrogenationBDOState,
        )
        deps_ok = True
    except ImportError:
        deps_ok = False

    stage1_pass = bool(py_ok and platform_ok and deps_ok)
    stages.append({
        "stage": 1,
        "name": "environment_and_platform_check",
        "check": "environment_and_platform_check",
        "passed": stage1_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Python {sys.version.split()[0]} on {sys.platform}; dependencies verified: "
            f"py_ok={py_ok}, deps_ok={deps_ok}."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 2: physical_constants_and_register_mappings
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    mw_ok = (
        math.isclose(MW_SUCCINATE_ESTER, 146.14, rel_tol=1e-3)
        and math.isclose(MW_GBL, 86.09, rel_tol=1e-3)
        and math.isclose(MW_BDO, 90.12, rel_tol=1e-3)
        and math.isclose(MW_H2, 2.016, rel_tol=1e-3)
        and math.isclose(MW_METHANOL, 32.04, rel_tol=1e-3)
        and math.isclose(MW_CARBON, 12.011, rel_tol=1e-3)
        and math.isclose(R_GAS_CONSTANT, 8.314462618, rel_tol=1e-4)
        and math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-4)
    )

    # Stoichiometric mass conservation checks
    # Step 1: SE + 2 H2 == GBL + 2 MeOH
    r1_mw = MW_SUCCINATE_ESTER + 2.0 * MW_H2
    p1_mw = MW_GBL + 2.0 * MW_METHANOL
    stoich1_ok = math.isclose(r1_mw, p1_mw, rel_tol=1e-3)

    # Step 2: GBL + 2 H2 == BDO
    r2_mw = MW_GBL + 2.0 * MW_H2
    p2_mw = MW_BDO
    stoich2_ok = math.isclose(r2_mw, p2_mw, rel_tol=1e-3)

    # Overall: SE + 4 H2 == BDO + 2 MeOH
    rtot_mw = MW_SUCCINATE_ESTER + 4.0 * MW_H2
    ptot_mw = MW_BDO + 2.0 * MW_METHANOL
    stoich_tot_ok = math.isclose(rtot_mw, ptot_mw, rel_tol=1e-3)

    reg_ok = (
        REG_PHA_H2_REACTOR_TEMP == "%R2780"
        and REG_PHA_H2_REACTOR_PRESSURE == "%R2781"
        and REG_PHA_H2_CONVERSION_EFFICIENCY == "%R2782"
        and REG_PHA_H2_BDO_SELECTIVITY == "%R2783"
        and REG_PHA_H2_SPACE_VELOCITY_LHSV == "%R2784"
        and REG_PHA_H2_CATALYST_ACTIVITY == "%R2785"
        and REG_PHA_H2_HYDROGEN_FLOW_SLPM == "%R2786"
        and REG_PHA_H2_DIAGNOSTIC_CODE == "%R2787"
    )
    coils_ok = (
        COIL_PHA_H2_REACTOR_ACTIVE == "%M648"
        and COIL_PHA_H2_HYDROGEN_FEED_VALVE == "%M649"
        and COIL_PHA_H2_EMERGENCY_DEPRESSURIZE == "%M650"
    )
    diag_codes_ok = (
        DIAG_OK == 0x0000
        and DIAG_ERR_THERMAL_RUNAWAY == 0xF991
        and DIAG_ERR_OVERPRESSURE_RUPTURE == 0xF992
        and DIAG_ERR_CATALYST_COKING == 0xF993
        and DIAG_ERR_HYDROGEN_STARVATION == 0xF994
        and DIAG_ERR_MASS_BALANCE_DIVERGENCE == 0xF995
    )

    stage2_pass = bool(
        mw_ok
        and stoich1_ok
        and stoich2_ok
        and stoich_tot_ok
        and reg_ok
        and coils_ok
        and diag_codes_ok
    )
    stages.append({
        "stage": 2,
        "name": "physical_constants_and_register_mappings",
        "check": "physical_constants_and_register_mappings",
        "passed": stage2_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Stoichiometric identity MW_SE+4*MW_H2={rtot_mw:.2f} == MW_BDO+2*MW_MEOH={ptot_mw:.2f}; "
            f"Registers %R2780..%R2787, coils %M648..%M650, and 5-tier diagnostic codes verified."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 3: catalytic_kinetics_and_selectivity
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    cfg = PHAHydrogenationBDOConfig()
    cfg_params_ok = (
        cfg.k1_forward > 0.0
        and cfg.ea1_j_mol > 0.0
        and cfg.k2_forward > 0.0
        and cfg.ea2_j_mol > 0.0
        and cfg.k_coking > 0.0
        and cfg.ea_coking_j_mol > 0.0
        and cfg.k_adsorb_se > 0.0
        and cfg.k_adsorb_gbl > 0.0
        and cfg.k_adsorb_bdo > 0.0
        and cfg.k_adsorb_h2 > 0.0
        and cfg.delta_h_rxn1_j_mol < 0.0
        and cfg.delta_h_rxn2_j_mol < 0.0
    )

    re_kin = PHAHydrogenationBDOEngine()
    r1_nom, r2_nom = re_kin.compute_rates(re_kin.state)

    st_hot = PHAHydrogenationBDOState(
        t_bed_kelvin=500.0,
        c_succinate_ester=re_kin.state.c_succinate_ester,
        c_gbl_intermediate=re_kin.state.c_gbl_intermediate,
        c_bdo_product=re_kin.state.c_bdo_product,
        c_h2_dissolved=re_kin.state.c_h2_dissolved,
    )
    r1_hot, r2_hot = re_kin.compute_rates(st_hot)

    st_cold = PHAHydrogenationBDOState(
        t_bed_kelvin=420.0,
        c_succinate_ester=re_kin.state.c_succinate_ester,
        c_gbl_intermediate=re_kin.state.c_gbl_intermediate,
        c_bdo_product=re_kin.state.c_bdo_product,
        c_h2_dissolved=re_kin.state.c_h2_dissolved,
    )
    r1_cold, r2_cold = re_kin.compute_rates(st_cold)

    arrhenius_ok = (
        r1_nom > 0.0
        and r2_nom > 0.0
        and r1_hot > r1_nom > r1_cold > 0.0
        and r2_hot > r2_nom > r2_cold > 0.0
    )

    selectivity_ok = (
        re_kin.bdo_selectivity_pct >= 0.0
        and re_kin.conversion_efficiency_pct >= 0.0
        and re_kin.h2_substrate_ratio > re_kin.cfg.h2_substrate_ratio_min
    )

    stage3_pass = bool(cfg_params_ok and arrhenius_ok and selectivity_ok)
    stages.append({
        "stage": 3,
        "name": "catalytic_kinetics_and_selectivity",
        "check": "catalytic_kinetics_and_selectivity",
        "passed": stage3_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Dual-step Langmuir-Hinshelwood kinetics: r1_hot={r1_hot:.4f} > nom={r1_nom:.4f} > cold={r1_cold:.4f}; "
            f"r2_hot={r2_hot:.4f} > nom={r2_nom:.4f} > cold={r2_cold:.4f} mol/(L*s); "
            f"Selectivity={re_kin.bdo_selectivity_pct:.1f}%; H2 ratio={re_kin.h2_substrate_ratio:.2f}."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 4: continuous_rk4_solver_and_mass_conservation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_rk4 = PHAHydrogenationBDOEngine()
    c_se_pre = re_rk4.state.c_succinate_ester
    c_gbl_pre = re_rk4.state.c_gbl_intermediate
    c_bdo_pre = re_rk4.state.c_bdo_product

    steps = 5 if quick else 15
    for _ in range(steps):
        re_rk4.step_rk4(dt=0.1)

    rk4_progress_ok = (
        re_rk4.state.c_succinate_ester < c_se_pre
        and (re_rk4.state.c_gbl_intermediate > c_gbl_pre or re_rk4.state.c_bdo_product > c_bdo_pre)
        and re_rk4.conversion_efficiency_pct > 0.0
    )
    cons_ok = re_rk4.conservation_residual < 1e-10

    # Multi-step-size convergence test (dt=0.01, dt=0.05, dt=0.1)
    conv_stable = True
    for dt_test in (0.01, 0.05, 0.1):
        test_re = PHAHydrogenationBDOEngine()
        test_re.step_rk4(dt=dt_test)
        if (
            test_re.state.c_succinate_ester <= 0.0
            or test_re.state.t_bed_kelvin <= 0.0
            or test_re.state.a_catalyst <= 0.0
            or test_re.conservation_residual >= 1e-10
        ):
            conv_stable = False
            break

    stage4_pass = bool(rk4_progress_ok and cons_ok and conv_stable)
    stages.append({
        "stage": 4,
        "name": "continuous_rk4_solver_and_mass_conservation",
        "check": "continuous_rk4_solver_and_mass_conservation",
        "passed": stage4_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"4th-Order RK4 dynamic integration over {steps} steps verified: C_se ({c_se_pre:.2f} -> {re_rk4.state.c_succinate_ester:.2f} mol/L); "
            f"Mass conservation residual {re_rk4.conservation_residual:.2e} < 1e-10."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 5: thermal_runaway_and_overpressure_trips
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. High reaction zone temperature trip (T_bed > 550 K)
    re_t = PHAHydrogenationBDOEngine()
    re_t.inject_thermal_runaway(temp_k=555.0)
    re_t.step_rk4(dt=0.05)
    trip_t_ok = (
        re_t.trip_active is True
        and re_t.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
        and re_t.emergency_depressurize_active is True
        and re_t.reactor_active is False
        and re_t.h2_feed_valve is False
        and re_t.reg_table.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is False
        and re_t.reg_table.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE) is False
        and re_t.reg_table.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is True
        and (re_t.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF991
    )

    # 2. High temperature rate-of-rise trip (dT_bed/dt > 15 K/s)
    re_r = PHAHydrogenationBDOEngine()
    re_r.inject_temperature_rate_runaway(rate_k_s=18.5)
    re_r.step_rk4(dt=0.05)
    trip_r_ok = (
        re_r.trip_active is True
        and re_r.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
    )

    # 3. Priority 2: Reactor overpressure rupture trip (P > 80.0 bar)
    re_p = PHAHydrogenationBDOEngine()
    re_p.inject_overpressure(pressure_bar=85.0)
    re_p.step_rk4(dt=0.05)
    trip_p_ok = (
        re_p.trip_active is True
        and re_p.diagnostic_code == DIAG_ERR_OVERPRESSURE_RUPTURE
        and re_p.emergency_depressurize_active is True
        and re_p.reactor_active is False
        and re_p.h2_feed_valve is False
        and re_p.reg_table.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE) is True
        and (re_p.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF992
    )

    # 4. Priority dominance: Thermal Runaway (P1) dominates Overpressure (P2)
    re_dom1 = PHAHydrogenationBDOEngine()
    re_dom1.state.t_bed_kelvin = 555.0
    re_dom1.state.p_reactor = 85.0
    re_dom1.step_rk4(dt=0.05)
    p1_dominates_p2 = re_dom1.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY

    stage5_pass = bool(trip_t_ok and trip_r_ok and trip_p_ok and p1_dominates_p2)
    stages.append({
        "stage": 5,
        "name": "thermal_runaway_and_overpressure_trips",
        "check": "thermal_runaway_and_overpressure_trips",
        "passed": stage5_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": "Safety interlocks verified: 0xF991 Thermal Runaway and 0xF992 Overpressure Rupture trips latched with emergency depressurization.",
    })

    # ------------------------------------------------------------------------
    # Stage 6: catalyst_coking_and_h2_starvation_diagnostics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. Catalyst coking / deactivation trip (activity < 30.0%)
    re_coking = PHAHydrogenationBDOEngine()
    re_coking.inject_catalyst_coking(activity=0.25)
    re_coking.step_rk4(dt=0.05)
    coking_ok = (
        re_coking.trip_active is True
        and re_coking.diagnostic_code == DIAG_ERR_CATALYST_COKING
        and re_coking.emergency_depressurize_active is True
        and (re_coking.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF993
        and re_coking.reg_table.read_word(REG_PHA_H2_CATALYST_ACTIVITY) == 250
    )

    # 2. Hydrogen starvation trip (H2/Substrate ratio < 2.0)
    re_starv = PHAHydrogenationBDOEngine()
    re_starv.inject_hydrogen_starvation(ratio=1.2)
    re_starv.step_rk4(dt=0.05)
    starv_ok = (
        re_starv.trip_active is True
        and re_starv.diagnostic_code == DIAG_ERR_HYDROGEN_STARVATION
        and re_starv.emergency_depressurize_active is True
        and (re_starv.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF994
    )

    # 3. Mass balance divergence trip (residual > 1e-4)
    re_div = PHAHydrogenationBDOEngine()
    re_div.inject_mass_divergence(residual=0.005)
    re_div.step_rk4(dt=0.05)
    div_ok = (
        re_div.trip_active is True
        and re_div.diagnostic_code == DIAG_ERR_MASS_BALANCE_DIVERGENCE
        and (re_div.reg_table.read_word(REG_PHA_H2_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF995
    )

    # 4. Priority hierarchy dominance: P2 > P3 > P4 > P5
    re_dom23 = PHAHydrogenationBDOEngine()
    re_dom23.state.p_reactor = 85.0
    re_dom23.state.a_catalyst = 0.20
    re_dom23.step_rk4(dt=0.05)
    p2_dominates_p3 = re_dom23.diagnostic_code == DIAG_ERR_OVERPRESSURE_RUPTURE

    re_dom34 = PHAHydrogenationBDOEngine()
    re_dom34.state.a_catalyst = 0.20
    re_dom34.inject_hydrogen_starvation(ratio=1.0)
    re_dom34.step_rk4(dt=0.05)
    p3_dominates_p4 = re_dom34.diagnostic_code == DIAG_ERR_CATALYST_COKING

    re_dom45 = PHAHydrogenationBDOEngine()
    re_dom45.inject_hydrogen_starvation(ratio=1.0)
    re_dom45.conservation_residual = 0.005
    re_dom45.step_rk4(dt=0.05)
    p4_dominates_p5 = re_dom45.diagnostic_code == DIAG_ERR_HYDROGEN_STARVATION

    stage6_pass = bool(
        coking_ok
        and starv_ok
        and div_ok
        and p2_dominates_p3
        and p3_dominates_p4
        and p4_dominates_p5
    )
    stages.append({
        "stage": 6,
        "name": "catalyst_coking_and_h2_starvation_diagnostics",
        "check": "catalyst_coking_and_h2_starvation_diagnostics",
        "passed": stage6_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            "Diagnostic trips 0xF993 (coking), 0xF994 (H2 starvation), 0xF995 (mass divergence) "
            "and full 5-tier fault hierarchy (0xF991 > 0xF992 > 0xF993 > 0xF994 > 0xF995) verified."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 7: register_table_synchronization_and_system_privilege
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_rt = PHAHydrogenationBDOEngine()
    re_rt.scan_step(dt=0.1)

    # USER privilege synchronization
    rt_user = RegisterTable()
    re_rt.sync_to_registers(rt_user, privilege=PrivilegeMode.USER)

    w_temp = rt_user.read_word(REG_PHA_H2_REACTOR_TEMP)
    w_press = rt_user.read_word(REG_PHA_H2_REACTOR_PRESSURE)
    w_conv = rt_user.read_word(REG_PHA_H2_CONVERSION_EFFICIENCY)
    w_sel = rt_user.read_word(REG_PHA_H2_BDO_SELECTIVITY)
    w_lhsv = rt_user.read_word(REG_PHA_H2_SPACE_VELOCITY_LHSV)
    w_act = rt_user.read_word(REG_PHA_H2_CATALYST_ACTIVITY)
    w_flow = rt_user.read_word(REG_PHA_H2_HYDROGEN_FLOW_SLPM)
    w_diag = rt_user.read_word(REG_PHA_H2_DIAGNOSTIC_CODE)

    b_act = rt_user.read_bit(COIL_PHA_H2_REACTOR_ACTIVE)
    b_feed = rt_user.read_bit(COIL_PHA_H2_HYDROGEN_FEED_VALVE)
    b_depress = rt_user.read_bit(COIL_PHA_H2_EMERGENCY_DEPRESSURIZE)

    user_sync_ok = (
        w_temp > 0
        and w_press > 0
        and w_conv >= 0
        and w_sel >= 0
        and w_lhsv > 0
        and w_act > 0
        and w_flow > 0
        and (w_diag & 0xFFFF) == 0x0000
        and b_act is True
        and b_feed is True
        and b_depress is False
    )

    # SYSTEM privilege synchronization
    rt_sys = RegisterTable()
    re_rt.sync_to_registers(rt_sys, privilege=PrivilegeMode.SYSTEM)
    sys_sync_ok = (
        rt_sys.read_word(REG_PHA_H2_REACTOR_TEMP) == w_temp
        and rt_sys.read_bit(COIL_PHA_H2_REACTOR_ACTIVE) is True
    )

    # DiagnosticCode signed/unsigned 16-bit mask equality
    d_obj = DiagnosticCode(0xF991)
    d_s = 0xF991 - 0x10000  # -1647
    mask_equality_ok = (
        d_obj == 0xF991
        and d_obj == d_s
        and (int(d_obj) & 0xFFFF) == 0xF991
        and hash(d_obj) == hash(0xF991)
    )

    stage7_pass = bool(user_sync_ok and sys_sync_ok and mask_equality_ok)
    stages.append({
        "stage": 7,
        "name": "register_table_synchronization_and_system_privilege",
        "check": "register_table_synchronization_and_system_privilege",
        "passed": stage7_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Horner OCS memory space %R2780..%R2787 and coils %M648..%M650 synchronized: "
            f"%R2780={w_temp}, %R2781={w_press}, %R2782={w_conv}, %R2783={w_sel}, %R2784={w_lhsv}, "
            f"%R2785={w_act}, %R2786={w_flow}, %R2787=0x{w_diag:04X}; signed mask (-1647 == 0xF991) verified."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 8: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_syntax_ok = verify_pha_hydrogenation_bdo_pure_st()

    st_bindings_ok = (
        "PHAHydrogenationBDOControl" in PHA_HYDROGENATION_BDO_PURE_ST_POU
        and "%R2780" in PHA_HYDROGENATION_BDO_PURE_ST_POU
        and "%R2781" in PHA_HYDROGENATION_BDO_PURE_ST_POU
        and "%R2782" in PHA_HYDROGENATION_BDO_PURE_ST_POU
        and "%R2783" in PHA_HYDROGENATION_BDO_PURE_ST_POU
        and "%R2784" in PHA_HYDROGENATION_BDO_PURE_ST_POU
        and "%R2785" in PHA_HYDROGENATION_BDO_PURE_ST_POU
        and "%R2786" in PHA_HYDROGENATION_BDO_PURE_ST_POU
        and "%R2787" in PHA_HYDROGENATION_BDO_PURE_ST_POU
        and "%M648" in PHA_HYDROGENATION_BDO_PURE_ST_POU
        and "%M649" in PHA_HYDROGENATION_BDO_PURE_ST_POU
        and "%M650" in PHA_HYDROGENATION_BDO_PURE_ST_POU
    )

    ladder_constructs = [
        "---[ ]---",
        "---[/]---",
        "---( )---",
        "---(/)---",
        "---(S)---",
        "---(R)---",
        "RUNG 1: START",
        "NETWORK 10",
        "XIC %M648",
    ]
    rejected_count = 0
    for frag in ladder_constructs:
        bad_code = f"PROGRAM BadLadder\nVAR x: BOOL; END_VAR\n{frag}\nEND_PROGRAM"
        try:
            SecurityGuard.assert_pure_st_content(bad_code)
        except LadderForbiddenError:
            rejected_count += 1

    stage8_pass = bool(st_syntax_ok and st_bindings_ok and (rejected_count == len(ladder_constructs)))
    stages.append({
        "stage": 8,
        "name": "pure_st_pou_and_anti_ladder_rejection",
        "check": "pure_st_pou_and_anti_ladder_rejection",
        "passed": stage8_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Pure ST POU 'PHAHydrogenationBDOControl' verified with correct %R and %M bindings; "
            f"{rejected_count}/{len(ladder_constructs)} ladder constructs rejected with LadderForbiddenError."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 9: continuous_soak_100_cycles_and_evidence_emission
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    re_soak = PHAHydrogenationBDOEngine()
    cycles_to_run = 25 if quick else 100
    soak_ok = True
    for _ in range(cycles_to_run):
        res = re_soak.scan_step(dt=0.1)
        if res.status != AgentStatus.SUCCESS:
            soak_ok = False
            break

    # Emergency depressurization & quench response test
    re_quench_test = PHAHydrogenationBDOEngine()
    re_quench_test.inject_thermal_runaway(temp_k=555.0)
    re_quench_test.step_rk4(dt=0.05)
    quench_latched = (
        re_quench_test.trip_active is True
        and re_quench_test.emergency_depressurize_active is True
        and re_quench_test.h2_feed_valve is False
        and re_quench_test.diagnostic_code == DIAG_ERR_THERMAL_RUNAWAY
    )

    t_bed_peak = re_quench_test.state.t_bed_kelvin
    for _ in range(25):
        re_quench_test.step_rk4(dt=0.2)

    t_bed_quenched = re_quench_test.state.t_bed_kelvin
    temp_drop = t_bed_peak - t_bed_quenched
    quench_effective = quench_latched and (temp_drop >= 15.0) and (t_bed_quenched < t_bed_peak)

    unit_ok = (
        re_soak.unit_id == "PHA_H2_BDO_REACTOR_W317"
        and re_soak.name == "PHAHydrogenationBDOEngine"
        and re_soak.priority == 50
        and re_soak.is_enabled is True
    )

    stage9_pass = bool(soak_ok and quench_effective and unit_ok and (re_soak.cycle_count == cycles_to_run))

    # Cryptographic digests
    pou_digest = hashlib.sha256(PHA_HYDROGENATION_BDO_PURE_ST_POU.encode("utf-8")).hexdigest()
    cfg_ev = PHAHydrogenationBDOConfig()
    model_digest = hashlib.sha256(
        json.dumps(cfg_ev.to_dict(), sort_keys=True).encode("utf-8")
    ).hexdigest()

    stages.append({
        "stage": 9,
        "name": "continuous_soak_100_cycles_and_evidence_emission",
        "check": "continuous_soak_100_cycles_and_evidence_emission",
        "passed": stage9_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Multi-cycle continuous fixed-bed hydrogenation soak executed for {cycles_to_run} cycles; "
            f"emergency quench dropped reaction bed temp by {temp_drop:.1f} K ({t_bed_peak:.1f} -> {t_bed_quenched:.1f} K); "
            f"deterministic SHA-256 digests emitted (POU: {pou_digest[:8]}..., Model: {model_digest[:8]}...)."
        ),
    })

    checks_passed = sum(1 for s in stages if s["passed"])
    total_checks = len(stages)
    all_passed = checks_passed == total_checks

    evidence: Dict[str, Any] = {
        "status": "success" if all_passed else "failed",
        "error_code": None if all_passed else "ERR_STAGE_VERIFICATION_FAILED",
        "details": (
            f"Wave {work_package} Industrial Catalytic PHA Hydrogenation & 1,4-BDO Verification "
            f"{'PASSED' if all_passed else 'FAILED'} ({checks_passed}/{total_checks} stages)."
        ),
        "stages_passed": checks_passed,
        "total_stages": total_checks,
        "data": {
            "work_package": work_package,
            "gate": "G7",
            "checks_passed": checks_passed,
            "total_checks": total_checks,
            "stages": stages,
            "tests": stages,
            "digests": {
                "pou_sha256": pou_digest,
                "model_sha256": model_digest,
            },
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }

    if output_path is not None:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


def run_pha_hydrogenation_bdo_verification(
    project_root: Optional[Any] = None,
    output_path: Optional[str] = None,
    work_package: str = "W317",
    quick: bool = False,
) -> Dict[str, Any]:
    """Compatibility entrypoint matching package API convention."""
    return execute_pha_hydrogenation_bdo_verification(
        output_path=output_path,
        work_package=work_package,
        quick=quick,
        project_root=project_root,
    )


run_pha_h2_bdo_verification = run_pha_hydrogenation_bdo_verification


def main(argv: Optional[List[str]] = None) -> int:
    """CLI Entrypoint for W317 PHA Hydrogenation & 1,4-BDO 9-Stage Verification Suite."""
    parser = argparse.ArgumentParser(
        description="Execute W317 Industrial Catalytic PHA Hydrogenation & 1,4-Butanediol Precursor Fixed-Bed Verification Suite."
    )
    parser.add_argument(
        "positional_output",
        nargs="?",
        default=None,
        help="Optional positional path to write JSON evidence artifact.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Path to output verification JSON evidence artifact (default: artifacts/simulation/pha_hydrogenation_bdo_evidence.json).",
    )
    parser.add_argument(
        "--quick",
        "-q",
        action="store_true",
        help="Execute rapid verification subset with reduced scan iteration cycles.",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W317",
        help="Work package identifier (default: W317).",
    )
    parser.add_argument(
        "--project-root",
        default=None,
        help="Root path of repository.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress terminal output and emit only exit code.",
    )
    parser.add_argument(
        "--json",
        "--json-only",
        action="store_true",
        help="Emit raw JSON report only (no ANSI stdout banner).",
    )

    args = parser.parse_args(argv)

    output_path = args.output or args.positional_output
    if not output_path:
        default_artifact = (
            REPO_ROOT / "artifacts" / "simulation" / "pha_hydrogenation_bdo_evidence.json"
        )
        output_path = str(default_artifact)

    if not args.quiet and not args.json:
        print(f"\n{ESC_BOLD}{ESC_CYAN}================================================================{ESC_RESET}")
        print(f"{ESC_BOLD}{ESC_CYAN}  JEV Cscape - Wave {args.work_package} PHA Hydrogenation & 1,4-BDO Verification{ESC_RESET}")
        print(f"{ESC_BOLD}{ESC_CYAN}================================================================{ESC_RESET}")
        print(f"  Target artifact: {output_path}")
        if args.quick:
            print(f"  Execution mode:  {ESC_YELLOW}QUICK (Rapid Subset){ESC_RESET}")
        print()

    t_start = time.perf_counter()
    evidence = execute_pha_hydrogenation_bdo_verification(
        output_path=output_path,
        work_package=args.work_package,
        quick=args.quick,
        project_root=args.project_root,
    )
    elapsed_total_ms = (time.perf_counter() - t_start) * 1000.0

    if args.json:
        print(json.dumps(evidence, indent=2))
        return 0 if evidence.get("status") == "success" else 1

    if not args.quiet:
        stages = evidence.get("data", {}).get("stages", [])
        for s in stages:
            print(
                format_stage_result(
                    stage=s.get("stage", "?"),
                    check=s.get("name", "unnamed"),
                    passed=bool(s.get("passed", False)),
                    timing_ms=s.get("timing_ms"),
                    details=s.get("details", ""),
                )
            )

        print(f"\n{ESC_BOLD}Summary:{ESC_RESET}")
        print(f"  Status:       {evidence.get('status')}")
        print(
            f"  Checks:       {evidence.get('data', {}).get('checks_passed')}/"
            f"{evidence.get('data', {}).get('total_checks')} passed"
        )
        print(f"  Total time:   {elapsed_total_ms:.2f} ms")
        print(f"  Evidence:     {output_path}\n")

    return 0 if evidence.get("status") == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
