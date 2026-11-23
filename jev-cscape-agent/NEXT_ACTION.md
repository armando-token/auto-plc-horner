# Next Immediate Actions: JEV Cscape Agent

> **Active Focus**: Gate G9 (Solicitud a proyecto industrial offline completo: W068–W075)  
> **Taxonomy**: Official Megaplan Section 17 Gates G0 through G12  
> **Gate Status**:  
> - **G0**: `passed` (Verified: environment, forensic inventory, Cscape 10.2 PE binary Build 10.2.751.4, companion DLL exports, registry, fail-closed safety, live Cscape startup on winsta0\Default, sandbox project open, CLI --help)  
> - **G1**: `passed` (Verified: false successes H01–H13 dismantled, modal dialog sweeper active, honest PARTIAL status enforced, navigation map, stability guardian, P1 field selection, channel matrix, pure ST parser with ERR_LADDER_FORBIDDEN)  
> - **G2**: `passed` (Verified: live Cscape visible GUI on winsta0\Default, exclusive single GUI boundary controller with file-backed mutex, Project Navigator UIA tree traversed without invented AutomationIds, fail-closed behavior verified)  
> - **G3**: `passed` (Verified: Live GUI Error Check 32826 clean compile 0 errors/0 warnings, download lockout 32827/33149, 10 edit+SaveAs+reopen durability runs on disposable copies of test_sandbox.csp with zero source overwrite)  
> - **G4**: `passed` (Verified: Pure-software closed-loop plant simulation offline/DEV [TESTED_MOCK], in-memory scan cycle, register state space %R, %AI, %AQ, %I, %Q, %M, %SR)  
> - **G5**: `passed` (Vision & Geometry Subsystem Live Acceptance Campaign Verified: scripts/g5_live_campaign.py executed live on winsta0\Default at 2026-10-13T23:25:44Z; 20/20 live visual targeting runs passed [100.0%: 10 Ladder Editor + 10 HMI Screen Editor]; 5/5 live negative controls passed [100.0%: stale frame rejection, moved window drift, out-of-bounds bounds guard, modal occlusion rejection, landmark mismatch]; baseline p1_base.csp strictly immutable [SHA-256: 5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881]; verified deliverables in artifacts/G5/g5_live_campaign_summary.json, artifacts/G5/g5_acceptance_summary.json, artifacts/G5/dataset/, W038-W043 visual capture, OCR, canvas geometry, and visual guard)  
> - **G6**: `passed` (Offline Acceptance & Knowledge Corpus Audited: scripts/g6_acceptance.py executed 30 verifiable queries with 100.0% recall [30/30 >= 90.0%], 5 plan requests [5/5 evaluated: 2 compatible, 2 incompatible with ERR_LADDER_FORBIDDEN and FAIL_CLOSED_HARDWARE_LOCKOUT, 1 missing data]; scripts/g6_audit.py verified 317 authentic technical documents [308 official Cscape 10.2 HTML manuals + 9 profiles/specs], 847 estimated pages, 3,240 chunks with 0/30 test suite answer contamination [artifacts/G6/g6_corpus_manifest.json]; scripts/g6_query.py provides BM25 retrieval with 200-char snippets, normalized register IDs [S008 = S8 = %S8 = %S0008 -> %S8 System Register table row at Rank 1], page title/heading boost ['backup a project' -> Manage Backups at Rank 1], and strict passage answering confidence [Mars / unsupported queries -> NOT FOUND])  
> - **G7**: `ACCEPTED` (Concrete Ladder Editor Element Placement: Verified ladder element placement, rung creation, contact/coil insertion on disposable copies; NOT ODE simulation)  
> - **G8**: `ACCEPTED` (Concrete HMI Screen Editor Multi-Object Placement & Variable Binding: 20/20 live runs accepted on disposable copies with authentic tag readback from tag/variable field, status bar count verification, multi-tier dialog retries; NOT Modbus scaling)  
> - **G9**: `READY_FOR_OPERATOR` (Solicitud a proyecto industrial offline completo [W068–W075]: Tank Training Family with 10 parameterized tasks [3 reserved variants: Tasks 08, 09, 10]; TaskSpec + Industrial IR + Requirement Traceability REQ Matrix [REQ-001..REQ-010]; Multi-stage verification pipeline [V2 schema pass, V3 static semantics pass, V4 offline project synthesis pass with native CFBF readback]; Task 06 intentional negative control with missing critical data stays pending with structured diagnosis ['DIAGNOSIS_MISSING_CRITICAL_DATA: Field(s) target_level, high_alarm are required...']; parametric change between tasks verified with zero old-value retention via CrossProjectParametricAbsenceVerifier; Real Jev planning query via https://api.typesafe.ai/v1/systemone (model: jev-latest); Live Cscape construction integrating proven G8 launch/dialog sequence [handle_startup_dialogs_and_wait_for_main_window with app/main_win], G3 variable declarations in Program Variables with pre-HMI commit sequence [Ctrl+S 57603, handle_confirmation_popups], G7 ladder rungs/contacts/coils with Column B coordinates (76, 25) and robust operand assignment in Dialog 108 with ALW_ON fallback to prevent unassigned ???? operands, full dismissal of modal compilation popups before HMI step [dismiss_error_check_modals], G8 HMI Screen 1 placement with strict title/class property dialog matching ['Numeric Data Properties', class #32770; rejecting compilation modals], SysTreeView32 category expansion [expand_all_treeview_items], pre-binding tag picker verification [verify_tag_in_hmi_picker], modal Error dialog interception [detect_and_handle_error_dialog], strict binding assertion preservation [assert verified_val == target_var], Win32 Error Check 32826 clean compile deferred strictly to the end after HMI [clean_compile verification], save 57603, and cold reopen verification; V5 simulation explicitly marked pending ['no simulator / offline only']; 49 unit tests passing across tests/test_g9_campaign.py and tests/test_g8_acceptance.py; assistant never runs live GUI; ready for operator execution on winsta0\Default: python scripts/g9_campaign.py --start-task 1 --end-task 10)  
> - **G10**: `open` (Multi-Rate Long-Term Soak & Runtime Stability: 100k-cycle offline simulation verified; live runtime soak pending)  
> - **G11**: `open` (Pre-Commissioning Safety Lockout & Interceptor Audit: hardware download and all 256 COM ports fail-closed locked out)  
> - **G12**: `open` (Field Commissioning & Hardware Hand-off: requires explicit Armando PLC OK for field authorization; fail-closed lockout permanently active)  
> **Safety Mode**: `FAIL_CLOSED` (Hardware download lockout active, zero COM ports, zero git remotes)  

---

## 1. Immediate Operational Sequence

### Action 1: Gate G9 Live Campaign Runner Deliverables [REBUILT & VERIFIED OFFLINE]
- **TaskSpec & Industrial IR Architecture** (`scripts/g9_campaign.py`): Immutable frozen dataclasses for 10 parameterized tasks in Tank Training Family.
- **3 Reserved Family Variants**: Tasks 08 (Chemical Dosing Reagent Tank), 09 (Two-Tank Cascade Inter-Transfer), and 10 (High-Viscosity Slurry Transfer).
- **REQ Traceability Matrix**: `REQ-001` through `REQ-010` bi-directionally mapped across TaskSpec parameters, variable allocations, ladder rungs, HMI objects, and verification stages.
- **Missing Data Negative Control**: Task 06 intentionally omits `target_level` and `high_alarm`; verified fail-closed transition to `pending` with `DIAGNOSIS_MISSING_CRITICAL_DATA` before any Cscape launch or file copy.
- **Parametric Absence Verifier**: `CrossProjectParametricAbsenceVerifier` scanning native CFBF streams (`/Contents`, `/V,`, `/Screen1`) across ASCII, UTF-16LE, and IEEE-754 binary floats to guarantee zero parameter leakage from Task N to N+1.
- **Real Jev Planning Query**: `JevG9Planner` calling `https://api.typesafe.ai/v1/systemone` (model: `jev-latest`) authenticated via `.env` `JEV_API_KEY`.
- **Live Cscape Construction Engine**: Proven paths for G8 launch and modal dialog handling, G3 variable declaration in Program Variables, G7 ladder rung and contact placement, G8 HMI Screen 1 placement and binding, Win32 Error Check `32826` clean compile, Save `57603`, and cold reopen verification.
- **Automated Unit Test Suite** (`tests/test_g9_campaign.py`): 29/29 unit tests passing in 3.06s including PILLAR 7 static AST + dynamic inspect.signature call-site audit.

### Action 2: Operator Review & Verification Command for G9 [READY FOR USER]
- **Runner Script**: `scripts/g9_campaign.py`
- **Execution Command (User Runs Live on winsta0\\Default)**:
  ```powershell
  python scripts/g9_campaign.py --start-task 1 --end-task 10
  ```
- **Fast Subset Execution**:
  ```powershell
  python scripts/g9_campaign.py --start-task 1 --end-task 2
  ```
- **Assistant Constraint**: Assistant **NEVER** executes live GUI scripts or launches `Cscape.exe`. Only the user executes live campaigns.
- **Campaign Verification Criteria**:
  - 10 parameterized tasks evaluated (9 passed, 1 pending with diagnosis, 0 failed).
  - 3/3 reserved variants passed (Tasks 08, 09, 10).
  - Baseline `work/disposable/p1_base.csp` strictly immutable (SHA-256: `5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881`).
  - Output summary: `artifacts/G9/g9_campaign_summary.json`.

---

## 2. Permanent Safety Invariants

- **Zero Physical PLC Connection**: Never connect to physical PLC hardware.
- **Fail-Closed Hardware Lockout**: COM ports `COM1`–`COM256`, companion flash tools (`PGMUpdateUtility.exe`, `DfuSeCommand.exe`, `STMFlashLoader.exe`, `WinJTAG.exe`), and Win32 download command IDs (`32827`, `33149`) are permanently blocked.
- **Single GUI Boundary**: Only ONE agent may interact with Cscape HWNDs on `winsta0\Default`.
- **Assistant Live Ban**: Assistant never runs live GUI or Cscape processes; user executes live campaigns.
- **No Ladder in ST**: Pure ST IEC 61131-3 parser rejects ladder constructs with `ERR_LADDER_FORBIDDEN`.
- **Local Git Only**: No git remotes, zero push.
- **Strict 4-State Contract**: All tools and agents return `success | failed | blocked | inconclusive`.
