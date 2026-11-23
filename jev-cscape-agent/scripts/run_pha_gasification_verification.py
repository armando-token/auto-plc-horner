#!/usr/bin/env python3
"""Verification Runner for Industrial Catalytic Polyhydroxyalkanoate (PHA) Gasification & Bio-Syngas Pyrolysis Moving-Bed ODE Simulation (W311).

Work Package: W311 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Moving-Bed Catalytic PHA Gasification 9-Stage Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: environment_and_platform_check
  Stage 2: physical_constants_and_register_mappings
  Stage 3: thermodynamic_syngas_equilibrium_and_kinetics
  Stage 4: continuous_rk4_solver_and_carbon_conservation
  Stage 5: bed_temperature_excursion_and_overpressure_trips
  Stage 6: tar_deposition_and_steam_starvation_diagnostics
  Stage 7: register_table_synchronization_and_system_privilege
  Stage 8: pure_st_pou_and_anti_ladder_rejection
  Stage 9: continuous_soak_100_cycles_and_evidence_emission

Generates:
  artifacts/simulation/pha_gasification_evidence.json
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

from jev_cscape.simulation.pha_gasification import (
    CARBON_FRACTION_CHAR,
    CARBON_FRACTION_PHA,
    CARBON_FRACTION_SYNGAS,
    COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE,
    COIL_PHA_GASIF_GASIFIER_ACTIVE,
    COIL_PHA_GASIF_SYNGAS_FLARE_VALVE,
    DIAG_ERR_BED_TEMPERATURE_EXCURSION,
    DIAG_ERR_CARBON_MASS_DIVERGENCE,
    DIAG_ERR_STEAM_STARVATION_CLINKERING,
    DIAG_ERR_SYNGAS_OVERPRESSURE_TRIP,
    DIAG_ERR_TAR_FORMATION_DEPOSITION,
    DIAG_OK,
    MW_CARBON,
    MW_CH4,
    MW_CO,
    MW_CO2,
    MW_H2,
    MW_H2O,
    MW_O2,
    MW_PHA_UNIT,
    PHA_GASIFICATION_PURE_ST_POU,
    REG_PHA_GASIF_BED_TEMP,
    REG_PHA_GASIF_CARBON_CONVERSION,
    REG_PHA_GASIF_COLD_GAS_EFFICIENCY,
    REG_PHA_GASIF_DIAGNOSTIC_CODE,
    REG_PHA_GASIF_FREEBOARD_TEMP,
    REG_PHA_GASIF_H2_CO_RATIO,
    REG_PHA_GASIF_STEAM_OXYGEN_DUTY,
    REG_PHA_GASIF_SYNGAS_PRESSURE,
    R_GAS_CONSTANT,
    T_ZERO_CELSIUS,
    Y_CHAR_PHA,
    Y_SYNGAS_CHAR,
    Y_SYNGAS_PHA,
    DiagnosticCode,
    PHAGasificationConfig,
    PHAGasificationEngine,
    PHAGasificationState,
    PHAGasificationStatusWord,
    verify_pha_gasification_pure_st,
)

# Optional aliases fallback
try:
    from jev_cscape.simulation.pha_gasification import (
        COIL_PHA_GASIF_ACTIVE,
        COIL_PHA_GASIF_FLARE,
        COIL_PHA_GASIF_PURGE,
        REG_PHA_GASIF_TBED,
        REG_PHA_GASIF_TFREEBOARD,
        REG_PHA_GASIF_PRESSURE,
        REG_PHA_GASIF_RATIO,
        REG_PHA_GASIF_CONV,
        REG_PHA_GASIF_CGE,
        REG_PHA_GASIF_DUTY,
        REG_PHA_GASIF_DIAG,
    )
except ImportError:
    COIL_PHA_GASIF_ACTIVE = COIL_PHA_GASIF_GASIFIER_ACTIVE
    COIL_PHA_GASIF_FLARE = COIL_PHA_GASIF_SYNGAS_FLARE_VALVE
    COIL_PHA_GASIF_PURGE = COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE
    REG_PHA_GASIF_TBED = REG_PHA_GASIF_BED_TEMP
    REG_PHA_GASIF_TFREEBOARD = REG_PHA_GASIF_FREEBOARD_TEMP
    REG_PHA_GASIF_PRESSURE = REG_PHA_GASIF_SYNGAS_PRESSURE
    REG_PHA_GASIF_RATIO = REG_PHA_GASIF_H2_CO_RATIO
    REG_PHA_GASIF_CONV = REG_PHA_GASIF_CARBON_CONVERSION
    REG_PHA_GASIF_CGE = REG_PHA_GASIF_COLD_GAS_EFFICIENCY
    REG_PHA_GASIF_DUTY = REG_PHA_GASIF_STEAM_OXYGEN_DUTY
    REG_PHA_GASIF_DIAG = REG_PHA_GASIF_DIAGNOSTIC_CODE

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


def execute_pha_gasification_verification(
    output_path: Optional[str] = None,
    work_package: str = "W311",
    quick: bool = False,
    project_root: Optional[Any] = None,
) -> Dict[str, Any]:
    """Execute the canonical 9-stage verification sequence for W311 PHA Gasification.

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
        from jev_cscape.simulation.pha_gasification import (
            PHAGasificationConfig,
            PHAGasificationEngine,
            PHAGasificationState,
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
        math.isclose(MW_PHA_UNIT, 86.09, rel_tol=1e-3)
        and math.isclose(MW_CARBON, 12.011, rel_tol=1e-3)
        and math.isclose(MW_CO, 28.010, rel_tol=1e-3)
        and math.isclose(MW_H2, 2.016, rel_tol=1e-3)
        and math.isclose(MW_CO2, 44.010, rel_tol=1e-3)
        and math.isclose(MW_CH4, 16.043, rel_tol=1e-3)
        and math.isclose(MW_H2O, 18.015, rel_tol=1e-3)
        and math.isclose(MW_O2, 31.999, rel_tol=1e-3)
        and math.isclose(R_GAS_CONSTANT, 8.314462618, rel_tol=1e-3)
        and math.isclose(T_ZERO_CELSIUS, 273.15, rel_tol=1e-3)
    )
    stoich_ok = (
        math.isclose(CARBON_FRACTION_PHA, (4.0 * MW_CARBON) / MW_PHA_UNIT, rel_tol=1e-4)
        and math.isclose(CARBON_FRACTION_CHAR, 1.0, rel_tol=1e-4)
        and math.isclose(CARBON_FRACTION_SYNGAS, 0.40, rel_tol=1e-4)
        and math.isclose(Y_CHAR_PHA, 0.15, rel_tol=1e-4)
        and math.isclose(Y_SYNGAS_CHAR, CARBON_FRACTION_CHAR / CARBON_FRACTION_SYNGAS, rel_tol=1e-4)
        and math.isclose(
            Y_SYNGAS_PHA,
            (CARBON_FRACTION_PHA - (Y_CHAR_PHA * CARBON_FRACTION_CHAR)) / CARBON_FRACTION_SYNGAS,
            rel_tol=1e-4,
        )
    )
    reg_ok = (
        REG_PHA_GASIF_BED_TEMP == "%R2720"
        and REG_PHA_GASIF_FREEBOARD_TEMP == "%R2721"
        and REG_PHA_GASIF_SYNGAS_PRESSURE == "%R2722"
        and REG_PHA_GASIF_H2_CO_RATIO == "%R2723"
        and REG_PHA_GASIF_CARBON_CONVERSION == "%R2724"
        and REG_PHA_GASIF_COLD_GAS_EFFICIENCY == "%R2725"
        and REG_PHA_GASIF_STEAM_OXYGEN_DUTY == "%R2726"
        and REG_PHA_GASIF_DIAGNOSTIC_CODE == "%R2727"
    )
    coils_ok = (
        COIL_PHA_GASIF_GASIFIER_ACTIVE == "%M634"
        and COIL_PHA_GASIF_SYNGAS_FLARE_VALVE == "%M635"
        and COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE == "%M636"
    )
    diag_codes_ok = (
        DIAG_OK == 0x0000
        and DIAG_ERR_BED_TEMPERATURE_EXCURSION == 0xF971
        and DIAG_ERR_SYNGAS_OVERPRESSURE_TRIP == 0xF972
        and DIAG_ERR_TAR_FORMATION_DEPOSITION == 0xF973
        and DIAG_ERR_CARBON_MASS_DIVERGENCE == 0xF974
        and DIAG_ERR_STEAM_STARVATION_CLINKERING == 0xF975
    )

    stage2_pass = bool(mw_ok and stoich_ok and reg_ok and coils_ok and diag_codes_ok)
    stages.append({
        "stage": 2,
        "name": "physical_constants_and_register_mappings",
        "check": "physical_constants_and_register_mappings",
        "passed": stage2_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Physical constants (MW_PHA={MW_PHA_UNIT}, MW_C={MW_CARBON}, MW_CO={MW_CO}, MW_H2={MW_H2}, R={R_GAS_CONSTANT}); "
            f"Registers %R2720..%R2727, Coils %M634..%M636, Diag 0xF971..0xF975 mapped deterministically."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 3: thermodynamic_syngas_equilibrium_and_kinetics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    cfg = PHAGasificationConfig()
    kinetics_params_ok = (
        cfg.k_pyro > 0.0
        and cfg.ea_pyro_j_mol > 0.0
        and cfg.delta_h_pyro_j_kg > 0.0
        and cfg.k_ox > 0.0
        and cfg.ea_ox_j_mol > 0.0
        and cfg.delta_h_ox_j_kg > 0.0
        and cfg.k_steam > 0.0
        and cfg.ea_steam_j_mol > 0.0
        and cfg.delta_h_steam_j_kg > 0.0
        and cfg.k_wgs > 0.0
        and cfg.k_reform > 0.0
        and cfg.ea_reform_j_mol > 0.0
        and cfg.y_tar_pyro > 0.0
    )

    g_kin = PHAGasificationEngine()
    r_pyro_nom, r_ox_nom, r_gasif_nom, _, _ = g_kin.compute_rates(g_kin.state)

    # Temperature sensitivity: Arrhenius rates increase monotonically with temperature
    st_hot = PHAGasificationState(t_bed=1100.0, c_pha=g_kin.state.c_pha, c_char=g_kin.state.c_char)
    r_pyro_hot, r_ox_hot, r_gasif_hot, _, _ = g_kin.compute_rates(st_hot)

    st_cold = PHAGasificationState(t_bed=950.0, c_pha=g_kin.state.c_pha, c_char=g_kin.state.c_char)
    r_pyro_cold, r_ox_cold, r_gasif_cold, _, _ = g_kin.compute_rates(st_cold)

    arrhenius_rates_ok = (
        r_pyro_nom > 0.0
        and r_ox_nom > 0.0
        and r_gasif_nom > 0.0
        and r_pyro_hot > r_pyro_nom > r_pyro_cold > 0.0
        and r_ox_hot > r_ox_nom > r_ox_cold > 0.0
        and r_gasif_hot > r_gasif_nom > r_gasif_cold > 0.0
    )

    ratio_nom = g_kin.h2_co_ratio
    ratio_ok = 1.0 <= ratio_nom <= 3.0
    cge_ok = g_kin.cold_gas_efficiency_pct >= 0.0

    stage3_pass = bool(kinetics_params_ok and arrhenius_rates_ok and ratio_ok and cge_ok)
    stages.append({
        "stage": 3,
        "name": "thermodynamic_syngas_equilibrium_and_kinetics",
        "check": "thermodynamic_syngas_equilibrium_and_kinetics",
        "passed": stage3_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Moving-bed Arrhenius devolatilization: r_pyro(950K)={r_pyro_cold:.4f} -> r_pyro(1050K)={r_pyro_nom:.4f} -> r_pyro(1100K)={r_pyro_hot:.4f} kg/(m³*s); "
            f"H2/CO Ratio={ratio_nom:.2f}; CGE={g_kin.cold_gas_efficiency_pct:.1f}%."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 4: continuous_rk4_solver_and_carbon_conservation
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    g4 = PHAGasificationEngine()
    c_pha_init = g4.state.c_pha
    c_syn_init = g4.state.c_syngas
    c_char_init = g4.state.c_char

    steps_s4 = 5 if quick else 15
    for _ in range(steps_s4):
        g4.step_rk4(dt=0.1)

    c_pha_end = g4.state.c_pha
    c_syn_end = g4.state.c_syngas
    c_char_end = g4.state.c_char
    res_s4 = g4.conservation_residual

    rk4_kinetics_ok = (
        c_pha_end < c_pha_init
        and c_syn_end > c_syn_init
        and res_s4 < 1e-10
    )

    # Multi-step-size convergence test (dt=0.01, dt=0.05, dt=0.1)
    stable_conv = True
    for dt_test in (0.01, 0.05, 0.1):
        g_dt = PHAGasificationEngine()
        g_dt.step_rk4(dt=dt_test)
        if (
            g_dt.state.c_pha <= 0.0
            or g_dt.state.c_syngas <= 0.0
            or g_dt.state.t_bed <= 0.0
            or g_dt.conservation_residual >= 1e-10
        ):
            stable_conv = False
            break

    stage4_pass = bool(rk4_kinetics_ok and stable_conv)
    stages.append({
        "stage": 4,
        "name": "continuous_rk4_solver_and_carbon_conservation",
        "check": "continuous_rk4_solver_and_carbon_conservation",
        "passed": stage4_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Continuous RK4 integration verified across {steps_s4} cycles: C_pha ({c_pha_init:.2f} -> {c_pha_end:.2f} kg/m³), "
            f"C_syngas={c_syn_end:.2f} kg/m³, C_char={c_char_end:.2f} kg/m³; Carbon residual={res_s4:.2e} < 1e-10."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 5: bed_temperature_excursion_and_overpressure_trips
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. Bed temperature excursion high temp trip (T_bed > 1150 K)
    g_t1 = PHAGasificationEngine()
    g_t1.state.t_bed = 1165.0
    g_t1.step_rk4(dt=0.05)
    t1_pass = (
        g_t1.trip_active is True
        and g_t1.diagnostic_code == DIAG_ERR_BED_TEMPERATURE_EXCURSION
        and g_t1.emergency_purge_active is True
        and g_t1.flare_valve_open is True
        and g_t1.gasifier_active is False
        and g_t1.reg_table.read_bit(COIL_PHA_GASIF_GASIFIER_ACTIVE) is False
        and g_t1.reg_table.read_bit(COIL_PHA_GASIF_SYNGAS_FLARE_VALVE) is True
        and g_t1.reg_table.read_bit(COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE) is True
        and (g_t1.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF971
    )

    # 2. Bed temperature excursion rate-of-rise trip (dT_bed/dt > 25 K/s)
    g_t2 = PHAGasificationEngine()
    g_t2.state.dt_bed_dt = 28.0
    g_t2.step_rk4(dt=0.05)
    t2_pass = (
        g_t2.trip_active is True
        and g_t2.diagnostic_code == DIAG_ERR_BED_TEMPERATURE_EXCURSION
        and (g_t2.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF971
    )

    # 3. Syngas overpressure trip (P_syngas > 40.0 bar)
    g_t3 = PHAGasificationEngine()
    g_t3.state.p_syngas = 42.5
    g_t3.step_rk4(dt=0.05)
    t3_pass = (
        g_t3.trip_active is True
        and g_t3.diagnostic_code == DIAG_ERR_SYNGAS_OVERPRESSURE_TRIP
        and g_t3.flare_valve_open is True
        and g_t3.emergency_purge_active is True
        and (g_t3.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF972
        and g_t3.reg_table.read_bit(COIL_PHA_GASIF_SYNGAS_FLARE_VALVE) is True
    )

    # 4. Priority dominance: Temperature Excursion (P1: 0xF971) dominates Overpressure (P2: 0xF972)
    g_dom1 = PHAGasificationEngine()
    g_dom1.state.t_bed = 1170.0
    g_dom1.state.p_syngas = 45.0
    g_dom1.step_rk4(dt=0.05)
    dom1_pass = g_dom1.diagnostic_code == DIAG_ERR_BED_TEMPERATURE_EXCURSION

    stage5_pass = bool(t1_pass and t2_pass and t3_pass and dom1_pass)
    stages.append({
        "stage": 5,
        "name": "bed_temperature_excursion_and_overpressure_trips",
        "check": "bed_temperature_excursion_and_overpressure_trips",
        "passed": stage5_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            "Safety trips 0xF971 (bed temperature excursion > 1150K & rate > 25K/s) and "
            "0xF972 (syngas overpressure trip > 40.0 bar) verified with N2 purge and flare actuation."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 6: tar_deposition_and_steam_starvation_diagnostics
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 1. Tar deposition trip (tar_fraction > 0.05)
    g_tar = PHAGasificationEngine()
    g_tar.tar_fraction = 0.065
    g_tar.step_rk4(dt=0.05)
    tar_pass = (
        g_tar.trip_active is True
        and g_tar.diagnostic_code == DIAG_ERR_TAR_FORMATION_DEPOSITION
        and (g_tar.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF973
        and g_tar.emergency_purge_active is True
        and g_tar.flare_valve_open is True
    )

    # 2. Carbon mass divergence trip (residual > 1e-4)
    g_div = PHAGasificationEngine()
    g_div.conservation_residual = 0.005
    g_div.step_rk4(dt=0.05)
    div_pass = (
        g_div.trip_active is True
        and g_div.diagnostic_code == DIAG_ERR_CARBON_MASS_DIVERGENCE
        and (g_div.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF974
    )

    # 3. Steam starvation clinkering trip (steam ratio < 0.3)
    g_steam = PHAGasificationEngine()
    g_steam.steam_ratio = 0.22
    g_steam.step_rk4(dt=0.05)
    steam_pass = (
        g_steam.trip_active is True
        and g_steam.diagnostic_code == DIAG_ERR_STEAM_STARVATION_CLINKERING
        and (g_steam.reg_table.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE) & 0xFFFF) == 0xF975
    )

    # 4. Priority ordering: 0xF972 > 0xF973 > 0xF974 > 0xF975
    g_dom2 = PHAGasificationEngine()
    g_dom2.state.p_syngas = 45.0
    g_dom2.tar_fraction = 0.08
    g_dom2.step_rk4(dt=0.05)
    p2_dominates_p3 = g_dom2.diagnostic_code == DIAG_ERR_SYNGAS_OVERPRESSURE_TRIP

    g_dom3 = PHAGasificationEngine()
    g_dom3.tar_fraction = 0.08
    g_dom3.conservation_residual = 0.005
    g_dom3.step_rk4(dt=0.05)
    p3_dominates_p4 = g_dom3.diagnostic_code == DIAG_ERR_TAR_FORMATION_DEPOSITION

    g_dom4 = PHAGasificationEngine()
    g_dom4.conservation_residual = 0.005
    g_dom4.steam_ratio = 0.20
    g_dom4.step_rk4(dt=0.05)
    p4_dominates_p5 = g_dom4.diagnostic_code == DIAG_ERR_CARBON_MASS_DIVERGENCE

    stage6_pass = bool(
        tar_pass and div_pass and steam_pass and p2_dominates_p3 and p3_dominates_p4 and p4_dominates_p5
    )
    stages.append({
        "stage": 6,
        "name": "tar_deposition_and_steam_starvation_diagnostics",
        "check": "tar_deposition_and_steam_starvation_diagnostics",
        "passed": stage6_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            "Diagnostic trips 0xF973 (tar deposition), 0xF974 (carbon divergence), 0xF975 (steam starvation) and "
            "complete 5-tier fault hierarchy (0xF971 > 0xF972 > 0xF973 > 0xF974 > 0xF975) verified."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 7: register_table_synchronization_and_system_privilege
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    g7 = PHAGasificationEngine()
    g7.scan_step(dt=0.1)
    rt7 = RegisterTable()
    g7.sync_to_registers(rt7, privilege=PrivilegeMode.USER)

    w_bed = rt7.read_word(REG_PHA_GASIF_BED_TEMP)
    w_fb = rt7.read_word(REG_PHA_GASIF_FREEBOARD_TEMP)
    w_press = rt7.read_word(REG_PHA_GASIF_SYNGAS_PRESSURE)
    w_ratio = rt7.read_word(REG_PHA_GASIF_H2_CO_RATIO)
    w_conv = rt7.read_word(REG_PHA_GASIF_CARBON_CONVERSION)
    w_cge = rt7.read_word(REG_PHA_GASIF_COLD_GAS_EFFICIENCY)
    w_duty = rt7.read_word(REG_PHA_GASIF_STEAM_OXYGEN_DUTY)
    w_diag = rt7.read_word(REG_PHA_GASIF_DIAGNOSTIC_CODE)

    b_act = rt7.read_bit(COIL_PHA_GASIF_GASIFIER_ACTIVE)
    b_flare = rt7.read_bit(COIL_PHA_GASIF_SYNGAS_FLARE_VALVE)
    b_purge = rt7.read_bit(COIL_PHA_GASIF_EMERGENCY_NITROGEN_PURGE)

    user_sync_ok = (
        w_bed > 0
        and w_fb > 0
        and w_press > 0
        and w_ratio > 0
        and w_conv >= 0
        and w_cge >= 0
        and w_duty > 0
        and (w_diag & 0xFFFF) == 0x0000
        and b_act is True
        and b_flare is False
        and b_purge is False
    )

    # SYSTEM privilege synchronization
    rt7_sys = RegisterTable()
    g7.sync_to_registers(rt7_sys, privilege=PrivilegeMode.SYSTEM)
    sys_sync_ok = (
        rt7_sys.read_word(REG_PHA_GASIF_BED_TEMP) == w_bed
        and rt7_sys.read_bit(COIL_PHA_GASIF_GASIFIER_ACTIVE) is True
    )

    # DiagnosticCode signed/unsigned 16-bit mask equality
    d_obj = DiagnosticCode(0xF971)
    d_s = 0xF971 - 0x10000  # -1679
    mask_equality_ok = (
        d_obj == 0xF971
        and d_obj == d_s
        and (int(d_obj) & 0xFFFF) == 0xF971
        and hash(d_obj) == hash(0xF971)
    )

    stage7_pass = bool(user_sync_ok and sys_sync_ok and mask_equality_ok)
    stages.append({
        "stage": 7,
        "name": "register_table_synchronization_and_system_privilege",
        "check": "register_table_synchronization_and_system_privilege",
        "passed": stage7_pass,
        "timing_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        "details": (
            f"Horner OCS register memory %R2720..%R2727 and coils %M634..%M636 synchronized: "
            f"%R2720={w_bed}, %R2721={w_fb}, %R2722={w_press}, %R2723={w_ratio}, %R2724={w_conv}, "
            f"%R2725={w_cge}, %R2726={w_duty}, %R2727=0x{w_diag:04X}; signed mask (-1679 == 0xF971) verified."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 8: pure_st_pou_and_anti_ladder_rejection
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_syntax_ok = verify_pha_gasification_pure_st()

    st_bindings_ok = (
        "PHAGasificationControl" in PHA_GASIFICATION_PURE_ST_POU
        and "%R2720" in PHA_GASIFICATION_PURE_ST_POU
        and "%R2721" in PHA_GASIFICATION_PURE_ST_POU
        and "%R2722" in PHA_GASIFICATION_PURE_ST_POU
        and "%R2723" in PHA_GASIFICATION_PURE_ST_POU
        and "%R2724" in PHA_GASIFICATION_PURE_ST_POU
        and "%R2725" in PHA_GASIFICATION_PURE_ST_POU
        and "%R2726" in PHA_GASIFICATION_PURE_ST_POU
        and "%R2727" in PHA_GASIFICATION_PURE_ST_POU
        and "%M634" in PHA_GASIFICATION_PURE_ST_POU
        and "%M635" in PHA_GASIFICATION_PURE_ST_POU
        and "%M636" in PHA_GASIFICATION_PURE_ST_POU
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
        "XIC %M634",
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
            f"Pure ST POU 'PHAGasificationControl' parsed successfully with correct register mappings; "
            f"{rejected_count}/{len(ladder_constructs)} ladder constructs rejected with LadderForbiddenError."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 9: continuous_soak_100_cycles_and_evidence_emission
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    g9 = PHAGasificationEngine()
    cycles_to_run = 25 if quick else 100
    soak_ok = True
    for _ in range(cycles_to_run):
        res = g9.scan_step(dt=0.1)
        if res.status != AgentStatus.SUCCESS:
            soak_ok = False
            break

    # Excursion & safety purge response test
    g_purge = PHAGasificationEngine()
    g_purge.state.t_bed = 1165.0
    g_purge.step_rk4(dt=0.05)
    purge_latched = (
        g_purge.trip_active is True
        and g_purge.emergency_purge_active is True
        and g_purge.flare_valve_open is True
        and g_purge.diagnostic_code == DIAG_ERR_BED_TEMPERATURE_EXCURSION
    )

    t_bed_peak = g_purge.state.t_bed
    for _ in range(25):
        g_purge.step_rk4(dt=0.2)

    t_bed_quenched = g_purge.state.t_bed
    temp_drop = t_bed_peak - t_bed_quenched
    purge_effective = purge_latched and (temp_drop >= 15.0) and (t_bed_quenched < t_bed_peak)

    # ILogicUnit interface verification
    unit_ok = (
        g9.unit_id == "PHA_GASIF_MOVING_BED_W311"
        and g9.name == "PHAGasificationEngine"
        and g9.priority == 50
        and g9.is_enabled is True
    )

    stage9_pass = bool(soak_ok and purge_effective and unit_ok and (g9.cycle_count == cycles_to_run))

    # Digests
    pou_digest = hashlib.sha256(PHA_GASIFICATION_PURE_ST_POU.encode("utf-8")).hexdigest()
    cfg_ev = PHAGasificationConfig()
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
            f"Multi-cycle continuous closed-loop soak executed for {cycles_to_run} cycles; "
            f"bed temperature excursion triggered purge dropping core temp by {temp_drop:.1f} K ({t_bed_peak:.1f} -> {t_bed_quenched:.1f} K); "
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
            f"Wave {work_package} Industrial Catalytic PHA Gasification & Bio-Syngas Pyrolysis Verification "
            f"{'PASSED' if all_passed else 'FAILED'} ({checks_passed}/{total_checks} stages)."
        ),
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


def run_pha_gasification_verification(
    project_root: Optional[Any] = None,
    output_path: Optional[str] = None,
    work_package: str = "W311",
    quick: bool = False,
) -> Dict[str, Any]:
    """Compatibility entrypoint matching package API convention."""
    return execute_pha_gasification_verification(
        output_path=output_path,
        work_package=work_package,
        quick=quick,
        project_root=project_root,
    )


def main(argv: Optional[List[str]] = None) -> int:
    """CLI Entrypoint for W311 PHA Gasification 9-Stage Verification Suite."""
    parser = argparse.ArgumentParser(
        description="Execute W311 Industrial Catalytic PHA Gasification & Bio-Syngas Pyrolysis 9-Stage Verification Suite."
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
        help="Path to output verification JSON evidence artifact (default: artifacts/simulation/pha_gasification_evidence.json).",
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
        default="W311",
        help="Work package identifier (default: W311).",
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
            REPO_ROOT / "artifacts" / "simulation" / "pha_gasification_evidence.json"
        )
        output_path = str(default_artifact)

    if not args.quiet and not args.json:
        print(f"\n{ESC_BOLD}{ESC_CYAN}================================================================{ESC_RESET}")
        print(f"{ESC_BOLD}{ESC_CYAN}  JEV Cscape - Wave {args.work_package} PHA Gasification Verification{ESC_RESET}")
        print(f"{ESC_BOLD}{ESC_CYAN}================================================================{ESC_RESET}")
        print(f"  Target artifact: {output_path}")
        if args.quick:
            print(f"  Execution mode:  {ESC_YELLOW}QUICK (Rapid Subset){ESC_RESET}")
        print()

    t_start = time.perf_counter()
    evidence = execute_pha_gasification_verification(
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
