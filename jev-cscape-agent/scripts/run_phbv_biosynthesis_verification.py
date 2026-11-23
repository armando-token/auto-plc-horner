#!/usr/bin/env python3
"""Verification Script for Industrial Polyhydroxyvalerate (PHV) / PHBV Copolymer Biosynthesis ODE Simulation (W281).

Work Package: W281 (Gate G7 Plant Process Modeling / Gate G4 Scan Cycle Simulation)
Classification: PRODUCTION_READY [Rigorous Biochemical Kinetics & Numerical Verification]
Status Contract: Strict 4-State JSON output & evidence emission.

Executes a deterministic 9-stage verification suite:
  Stage 1: initial_state_and_biomass_growth (verify initial inoculant growth in Phase 1)
  Stage 2: substrate_glucose_depletion_kinetics (verify glucose consumption and uptake rates)
  Stage 3: nitrogen_exhaustion_and_polymer_induction (verify transition to Phase 2, %M564 asserted)
  Stage 4: valerate_precursor_dosing_and_hv_molar_fraction (verify valerate dosing increases HV molar fraction %R2426)
  Stage 5: dissolved_oxygen_limitation_and_aeration_response (verify DO dynamics, kLa transfer, and oxygen demand)
  Stage 6: thermal_and_acidification_fault_trips (verify trips 0xF601..0xF604, fail-safe shutdown)
  Stage 7: mass_conservation_and_elemental_residual_verification (verify carbon balance residuals < 1e-10)
  Stage 8: horner_ocs_register_sync (verify %R2420..%R2427 and %M564..%M566 in RegisterTable)
  Stage 9: pure_st_pou_and_ladder_rejection (verify ST POU syntax and anti-ladder check)

Generates:
  artifacts/simulation/phbv_biosynthesis_evidence.json
"""

from __future__ import annotations

import argparse
import json
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
from jev_cscape.iec.st_parser import POUType, STParser, STVariable
from jev_cscape.security.exceptions import LadderForbiddenError
from jev_cscape.security.guard import SecurityGuard
from jev_cscape.simulation.register_table import PrivilegeMode, RegisterTable
from jev_cscape.simulation.phbv_biosynthesis import (
    BIOMASS_NOMINAL_G_L,
    GLUCOSE_NOMINAL_G_L,
    PRECURSOR_NOMINAL_G_L,
    DISSOLVED_OXYGEN_NOMINAL_PCT,
    POLYMER_NOMINAL_G_L,
    HV_FRACTION_NOMINAL_MOL_PCT,
    TEMP_NOMINAL_C,
    DO_STARVATION_TRIP_PCT,
    PRECURSOR_OVERCONC_TRIP_G_L,
    TEMP_RUNAWAY_TRIP_C,
    CONTAMINATION_PH_TRIP_MIN,
    REG_PHBV_TEMP_SCALED,
    REG_PHBV_BIOMASS_SCALED,
    REG_PHBV_GLUCOSE_SCALED,
    REG_PHBV_PRECURSOR_SCALED,
    REG_PHBV_DO_SCALED,
    REG_PHBV_POLYMER_SCALED,
    REG_PHBV_HV_FRACTION_SCALED,
    REG_PHBV_GROWTH_STATE_SCALED,
    COIL_PHBV_INDUCTION_ACTIVE,
    COIL_PHBV_FEED_PUMP_ACTIVE,
    COIL_PHBV_HARVEST_ALARM,
    PHBV_BIOSYNTHESIS_PURE_ST_POU,
    PhbvTripCode,
    PhbvMetabolicState,
    PhbvStatusBits,
    PhbvBiosynthesisConfig,
    PhbvBiosynthesisState,
    PhbvBiosynthesisReactor,
    verify_phbv_biosynthesis_pure_st,
)

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


def execute_phbv_verification_suite(
    output_path: Optional[Union[str, Path]] = None,
    work_package: str = "W281",
) -> Dict[str, Any]:
    """Execute the canonical 9-stage verification sequence for W281 PHBV Biosynthesis."""
    start_time = time.time()
    test_results: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------------
    # Stage 1: initial_state_and_biomass_growth (verify initial inoculant growth in Phase 1)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim1 = PhbvBiosynthesisReactor()
    sim1.set_phase_1_growth()
    # Inoculant conditions: lower initial biomass, high nitrogen (Phase 1)
    sim1.state.biomass_conc_g_l = 2.5
    sim1.state.substrate_glucose_g_l = 20.0
    sim1.state.nitrogen_exhausted_active = False
    sim1._evaluate_safety_interlocks()
    sim1._sync_registers()

    mu_init = sim1.state.specific_growth_rate_h1
    x_start = sim1.state.biomass_conc_g_l
    m564_init = sim1.state.nitrogen_exhausted_active

    for _ in range(50):
        sim1.rk4_step(dt=0.1)

    x_final = sim1.state.biomass_conc_g_l
    c1 = bool(
        mu_init > 0.01
        and x_final >= x_start
        and m564_init is False
        and sim1.state.feed_pump_active is True
        and sim1.state.trip_code == PhbvTripCode.NORMAL
    )
    t1_ms = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 1,
        "name": "initial_state_and_biomass_growth",
        "check": "initial_state_and_biomass_growth",
        "passed": c1,
        "timing_ms": t1_ms,
        "details": (
            f"Phase 1 inoculant growth verified: X0={x_start:.2f} g/L -> X_final={x_final:.2f} g/L, "
            f"mu_growth={mu_init:.4f} 1/h, %M564={m564_init} (False), %M565={sim1.state.feed_pump_active} (True)."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 2: substrate_glucose_depletion_kinetics (verify glucose consumption and uptake rates)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim2 = PhbvBiosynthesisReactor()
    # Batch consumption setup: disable feeds to verify substrate consumption kinetics
    sim2.config.fed_batch_mode = False
    sim2.state.feed_pump_active = False
    sim2.state.biomass_conc_g_l = 20.0
    sim2.state.substrate_glucose_g_l = 15.0
    sim2._evaluate_safety_interlocks()

    s_start = sim2.state.substrate_glucose_g_l
    kin2 = sim2.compute_kinetics(
        sim2.state.biomass_conc_g_l,
        sim2.state.substrate_glucose_g_l,
        sim2.state.precursor_valerate_g_l,
        sim2.state.dissolved_oxygen_pct,
        sim2.state.polymer_accumulation_g_l,
        sim2.state.hv_molar_fraction_pct,
    )
    r_p = kin2["r_p"]
    our = kin2["our"]

    for _ in range(50):
        sim2.rk4_step(dt=0.1)

    s_end = sim2.state.substrate_glucose_g_l
    c2 = bool(
        r_p > 0.0
        and our > 0.0
        and s_end <= s_start
    )
    t2_ms = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 2,
        "name": "substrate_glucose_depletion_kinetics",
        "check": "substrate_glucose_depletion_kinetics",
        "passed": c2,
        "timing_ms": t2_ms,
        "details": (
            f"Glucose consumption kinetics verified: S_start={s_start:.2f} g/L -> S_end={s_end:.2f} g/L, "
            f"polymer synthesis rate r_p={r_p:.3f} g/(L*h), oxygen uptake OUR={our:.1f} % sat/h."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 3: nitrogen_exhaustion_and_polymer_induction (verify transition to Phase 2, %M564 asserted)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim3 = PhbvBiosynthesisReactor()
    # Phase 1: growth active, induction coil %M564 = False
    sim3.set_phase_1_growth()
    m564_phase1 = sim3.state.nitrogen_exhausted_active

    # Transition to Phase 2: nitrogen exhaustion triggers polymer induction %M564 = True
    sim3.set_phase_2_accumulation()
    m564_phase2 = sim3.state.nitrogen_exhausted_active

    # Advance simulation and verify active polymer synthesis
    sim3.rk4_step(dt=0.1)
    kin3 = sim3.compute_kinetics(
        sim3.state.biomass_conc_g_l,
        sim3.state.substrate_glucose_g_l,
        sim3.state.precursor_valerate_g_l,
        sim3.state.dissolved_oxygen_pct,
        sim3.state.polymer_accumulation_g_l,
        sim3.state.hv_molar_fraction_pct,
    )
    c3 = bool(
        m564_phase1 is False
        and m564_phase2 is True
        and kin3["r_p"] > 0.0
        and sim3.state.metabolic_state_code == PhbvMetabolicState.POLYMER_INDUCTION
    )
    t3_ms = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 3,
        "name": "nitrogen_exhaustion_and_polymer_induction",
        "check": "nitrogen_exhaustion_and_polymer_induction",
        "passed": c3,
        "timing_ms": t3_ms,
        "details": (
            f"Phase transition verified: Phase 1 %M564={m564_phase1} (False) -> "
            f"Phase 2 %M564={m564_phase2} (True), polymer synthesis r_p={kin3['r_p']:.3f} g/(L*h)."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 4: valerate_precursor_dosing_and_hv_molar_fraction (verify valerate dosing increases HV %R2426)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim4_a = PhbvBiosynthesisReactor()
    kin_a = sim4_a.compute_kinetics(35.0, 15.0, 0.0, 35.0, 50.0, 0.0)
    fhv_syn_zero = kin_a["f_hv_syn"]

    sim4_b = PhbvBiosynthesisReactor()
    kin_b = sim4_b.compute_kinetics(35.0, 15.0, 2.5, 35.0, 50.0, 15.5)
    fhv_syn_dosed = kin_b["f_hv_syn"]

    tbl4 = RegisterTable()
    sim4_b.sync_to_registers(tbl4)
    r2426_val = tbl4.read_word("%R2426")

    c4 = bool(
        fhv_syn_zero == 0.0
        and fhv_syn_dosed > 10.0
        and fhv_syn_dosed > fhv_syn_zero
        and r2426_val > 0
    )
    t4_ms = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 4,
        "name": "valerate_precursor_dosing_and_hv_molar_fraction",
        "check": "valerate_precursor_dosing_and_hv_molar_fraction",
        "passed": c4,
        "timing_ms": t4_ms,
        "details": (
            f"Precursor dosing verified: S_v=0.0 g/L -> HV={fhv_syn_zero:.1f} mol%; "
            f"S_v=2.5 g/L -> HV={fhv_syn_dosed:.1f} mol%, %R2426={r2426_val} (155 = 15.5 mol%)."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 5: dissolved_oxygen_limitation_and_aeration_response (verify DO dynamics, kLa transfer)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim5 = PhbvBiosynthesisReactor()
    kin5 = sim5.compute_kinetics(
        sim5.state.biomass_conc_g_l,
        sim5.state.substrate_glucose_g_l,
        sim5.state.precursor_valerate_g_l,
        sim5.state.dissolved_oxygen_pct,
        sim5.state.polymer_accumulation_g_l,
        sim5.state.hv_molar_fraction_pct,
    )
    kla = kin5["kla"]
    otr = kla * (sim5.config.do_sat_pct - sim5.state.dissolved_oxygen_pct)
    our = kin5["our"]

    sim5_low = PhbvBiosynthesisReactor()
    sim5_low.config.kla_nominal_h1 = 30.0
    sim5_low.state.dissolved_oxygen_pct = 40.0
    for _ in range(50):
        sim5_low.rk4_step(dt=0.1)
    do_depleted = sim5_low.state.dissolved_oxygen_pct

    sim5_high = PhbvBiosynthesisReactor()
    sim5_high.config.kla_nominal_h1 = 200.0
    sim5_high.state.dissolved_oxygen_pct = 20.0
    for _ in range(50):
        sim5_high.rk4_step(dt=0.1)
    do_restored = sim5_high.state.dissolved_oxygen_pct

    c5 = bool(
        otr > 0.0
        and our > 0.0
        and kla > 0.0
        and do_depleted < 40.0
        and do_restored > 20.0
    )
    t5_ms = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 5,
        "name": "dissolved_oxygen_limitation_and_aeration_response",
        "check": "dissolved_oxygen_limitation_and_aeration_response",
        "passed": c5,
        "timing_ms": t5_ms,
        "details": (
            f"Aeration dynamics verified: baseline OTR={otr:.1f} %/h, OUR={our:.1f} %/h, Kla={kla:.1f} 1/h; "
            f"low Kla=30: DO dropped to {do_depleted:.1f}%; high Kla=200: DO restored to {do_restored:.1f}%."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 6: thermal_and_acidification_fault_trips (verify trips 0xF601..0xF604, fail-safe shutdown)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    # 0xF601: DO Starvation trip
    sim6_1 = PhbvBiosynthesisReactor()
    sim6_1.inject_fault("oxygen")
    t1 = bool(
        sim6_1.state.trip_code == PhbvTripCode.DO_STARVATION
        and not sim6_1.state.feed_pump_active
        and not sim6_1.state.nitrogen_exhausted_active
        and sim6_1.state.batch_harvest_or_acid_alarm is True
    )

    # 0xF602: Precursor Overconcentration trip
    sim6_2 = PhbvBiosynthesisReactor()
    sim6_2.inject_fault("precursor")
    t2 = bool(
        sim6_2.state.trip_code == PhbvTripCode.PRECURSOR_OVERCONC
        and not sim6_2.state.feed_pump_active
        and not sim6_2.state.nitrogen_exhausted_active
        and sim6_2.state.batch_harvest_or_acid_alarm is True
    )

    # 0xF603: Thermal Runaway trip
    sim6_3 = PhbvBiosynthesisReactor()
    sim6_3.inject_fault("thermal")
    t3 = bool(
        sim6_3.state.trip_code == PhbvTripCode.THERMAL_RUNAWAY
        and not sim6_3.state.feed_pump_active
        and not sim6_3.state.nitrogen_exhausted_active
        and sim6_3.state.batch_harvest_or_acid_alarm is True
    )

    # 0xF604: Acidification / Contamination trip
    sim6_4 = PhbvBiosynthesisReactor()
    sim6_4.inject_fault("contamination")
    t4 = bool(
        sim6_4.state.trip_code == PhbvTripCode.CONTAMINATION_PH_DROP
        and not sim6_4.state.feed_pump_active
        and not sim6_4.state.nitrogen_exhausted_active
        and sim6_4.state.batch_harvest_or_acid_alarm is True
    )

    c6 = bool(t1 and t2 and t3 and t4)
    t6_ms = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 6,
        "name": "thermal_and_acidification_fault_trips",
        "check": "thermal_and_acidification_fault_trips",
        "passed": c6,
        "timing_ms": t6_ms,
        "details": (
            "Safety interlocks verified: 0xF601 (DO starvation), 0xF602 (precursor overconc), "
            "0xF603 (thermal runaway), 0xF604 (contamination); all enforce feed pump stop (%M565=False) and alarm (%M566=True)."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 7: mass_conservation_and_elemental_residual_verification (verify carbon balance residuals < 1e-10)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    sim7 = PhbvBiosynthesisReactor()
    sim7.rk4_step(dt=0.02)
    res_c = sim7.state.carbon_mass_balance_residual
    res_stoich = sim7.state.stoichiometric_mass_balance_residual
    res_tot = sim7.state.total_mass_balance_residual

    c7 = bool(
        res_c < 1.0e-10
        and res_stoich < 1.0e-10
        and res_tot < 1.0e-10
    )
    t7_ms = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 7,
        "name": "mass_conservation_and_elemental_residual_verification",
        "check": "mass_conservation_and_elemental_residual_verification",
        "passed": c7,
        "timing_ms": t7_ms,
        "details": (
            f"Mass conservation verified: carbon residual={res_c:.2e} kg/s, "
            f"stoichiometric residual={res_stoich:.2e} kg/s, total residual={res_tot:.2e} kg/s (< 1e-10 threshold)."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 8: horner_ocs_register_sync (verify %R2420..%R2427 and %M564..%M566 in RegisterTable)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    tbl8 = RegisterTable()
    sim8 = PhbvBiosynthesisReactor(register_table=tbl8)
    sim8.reset()
    sim8.sync_to_registers(tbl8)

    r2420 = tbl8.read_word("%R2420")
    r2421 = tbl8.read_word("%R2421")
    r2422 = tbl8.read_word("%R2422")
    r2423 = tbl8.read_word("%R2423")
    r2424 = tbl8.read_word("%R2424")
    r2425 = tbl8.read_word("%R2425")
    r2426 = tbl8.read_word("%R2426")
    r2427 = tbl8.read_word("%R2427")

    m564 = tbl8.read_bit("%M564")
    m565 = tbl8.read_bit("%M565")
    m566 = tbl8.read_bit("%M566")

    c8 = bool(
        r2420 == 300
        and r2421 == 350
        and r2422 == 150
        and r2423 == 25
        and r2424 == 350
        and r2425 == 550
        and r2426 == 155
        and (r2427 & 0xFF) == 2  # State 2: POLYMER_INDUCTION
        and m564 is True
        and m565 is True
        and m566 is False
    )
    t8_ms = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 8,
        "name": "horner_ocs_register_sync",
        "check": "horner_ocs_register_sync",
        "passed": c8,
        "timing_ms": t8_ms,
        "details": (
            f"Horner OCS register sync verified: %R2420..%R2427 = [{r2420}, {r2421}, {r2422}, {r2423}, "
            f"{r2424}, {r2425}, {r2426}, {r2427}], coils %M564..%M566 = [{m564}, {m565}, {m566}]."
        ),
    })

    # ------------------------------------------------------------------------
    # Stage 9: pure_st_pou_and_ladder_rejection (verify ST POU syntax and anti-ladder check)
    # ------------------------------------------------------------------------
    t0 = time.perf_counter()
    st_val = verify_phbv_biosynthesis_pure_st()

    bad_contacts = False
    bad_coils = False
    bad_rungs = False

    try:
        SecurityGuard.assert_pure_st_content("PROGRAM Bad ---[ ]--- END_PROGRAM")
    except LadderForbiddenError:
        bad_contacts = True

    try:
        SecurityGuard.assert_pure_st_content("PROGRAM Bad ---( )--- END_PROGRAM")
    except LadderForbiddenError:
        bad_coils = True

    try:
        SecurityGuard.assert_pure_st_content("PROGRAM Bad RUNG END_PROGRAM")
    except LadderForbiddenError:
        bad_rungs = True

    c9 = bool(st_val and bad_contacts and bad_coils and bad_rungs)
    t9_ms = (time.perf_counter() - t0) * 1000.0
    test_results.append({
        "stage": 9,
        "name": "pure_st_pou_and_ladder_rejection",
        "check": "pure_st_pou_and_ladder_rejection",
        "passed": c9,
        "timing_ms": t9_ms,
        "details": (
            "PhbvBiosynthesisSync POU AST validated with STParser & SecurityGuard; "
            "forbidden ladder constructs (contacts, coils, rungs) rejected with LadderForbiddenError."
        ),
    })

    # ------------------------------------------------------------------------
    # Aggregate Summary & JSON Evidence Export
    # ------------------------------------------------------------------------
    total_stages = len(test_results)
    passed_count = sum(1 for t in test_results if t.get("passed", False))
    all_passed = (passed_count == total_stages)
    duration_s = time.time() - start_time

    status = "success" if all_passed else "failed"
    error_code = None if all_passed else "VERIFICATION_FAILED"
    details = (
        f"PHBV copolymer biosynthesis simulation verification passed ({passed_count}/{total_stages} stages passed)."
        if all_passed
        else f"PHBV copolymer biosynthesis simulation verification failed ({passed_count}/{total_stages} stages passed)."
    )

    evidence: Dict[str, Any] = {
        "status": status,
        "error_code": error_code,
        "details": details,
        "data": {
            "work_package": work_package,
            "stages_passed": passed_count,
            "passed_stages": passed_count,
            "total_stages": total_stages,
            "checks_passed": passed_count,
            "total_checks": total_stages,
            "duration_seconds": duration_s,
            "elapsed_ms": duration_s * 1000.0,
            "stages": test_results,
            "results": test_results,
            "tests": test_results,
        },
    }

    target_path = output_path
    if target_path:
        p = Path(target_path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    return evidence


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute W281 PHBV Biosynthesis 9-Stage Verification Suite."
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
        help="Path to output verification JSON evidence artifact.",
    )
    parser.add_argument(
        "--work-package",
        type=str,
        default="W281",
        help="Work package identifier (default: W281).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON directly to stdout.",
    )
    args = parser.parse_args(argv)

    # Determine output target path
    default_evidence = REPO_ROOT / "artifacts" / "simulation" / "phbv_biosynthesis_evidence.json"
    out_path_str = args.output or args.positional_output or str(default_evidence)
    out_path = Path(out_path_str).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    t0 = time.perf_counter()
    result = execute_phbv_verification_suite(output_path=out_path, work_package=args.work_package)
    elapsed_total_ms = (time.perf_counter() - t0) * 1000.0

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result.get("status") == "success" else 1

    print("\n" + "=" * 76)
    print(f"  {args.work_package} PHBV BIOSYNTHESIS 9-STAGE VERIFICATION SUITE")
    print("=" * 76 + "\n")

    stages = result.get("data", {}).get("stages", [])
    for st in stages:
        st_num = st.get("stage", "?")
        check_name = st.get("name", st.get("check", "Stage Check"))
        passed = st.get("passed", False)
        details = st.get("details", "")
        timing = st.get("timing_ms")
        print(format_stage_result(st_num, check_name, passed, timing_ms=timing, details=details))

    overall_status = result.get("status", "failed")
    passed_count = result.get("data", {}).get("checks_passed", 0)
    total_count = result.get("data", {}).get("total_checks", len(stages))

    print("\n" + "-" * 76)
    if overall_status == "success":
        print(
            f"  RESULT: {ESC_GREEN}{ESC_BOLD}SUCCESS{ESC_RESET} "
            f"({passed_count}/{total_count} checks passed in {elapsed_total_ms:.1f}ms)"
        )
    else:
        print(
            f"  RESULT: {ESC_RED}{ESC_BOLD}FAILED{ESC_RESET} "
            f"({passed_count}/{total_count} checks passed in {elapsed_total_ms:.1f}ms)"
        )
    print(f"  Evidence written to: {out_path}\n")

    return 0 if overall_status == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
