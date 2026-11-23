# MEGAPLAN: Jev Autonomous Cscape Agent for Windows
**Document Reference**: `MEGAPLAN_JEV_CSCAPE_WINDOWS.md`  
**Standard**: Official Megaplan Section 17 Gate Governance (G0 through G12)  
**Target Environment**: Windows 11 x64 (`winsta0\Default`), Horner APG Cscape 10.2 (Build 10.2.751.4)  
**Safety Classification**: Fail-Closed Hardware Lockout, Zero-Trust Physical Communication Ports  

---

## 1. Executive Megaplan Overview & Gate Taxonomy

The Megaplan establishes an evidence-gated progression for full autonomous orchestration of Horner APG Cscape 10.2 on Windows using Jev remote reasoning, FastMCP stdio client tooling, and native Compound File Binary Format (CFBF) project manipulation.

| Gate | Title | Scope & Mandate | Status |
| :---: | :--- | :--- | :---: |
| **G0** | Foundation, Forensics & Environment Inventory | Binary PE header, DLL exports, registry keys, doctor pass, zero secrets, live launch, sandbox project open, CLI --help, documentation suite (W001–W009, W037). | `PASSED` |
| **G1** | False Success Dismantling & Dialog Sweepers | Modal dialog sweeper (#32770, Tip of the Day), honest PARTIAL status, zero silent mocks, navigation map, stability report, P1 selection, channel matrix, pure ST parser (W010, W011, W012; H01–H13 dismantled). | `PASSED` |
| **G2** | Live Visible GUI Control on Interactive Desktop | Cscape window visible on `winsta0\Default`, Project Navigator visible, single GUI agent boundary strictly maintained (W013, W014). | `PASSED` |
| **G3** | Live GUI Error Check Clean Compile & Download Lockout | Clean compile (0 errors, 0 warnings), MFC ListBox 372 compiler output scraped, download lockout (32827/33149), 10 edit+SaveAs+reopen durability cycles on copies of `p1_base.csp` with clean reopen decl count 24 (W015–W017, W025–W030). | `PASSED` |
| **G4** | Pure-Software Simulation & Remote AI Reasoning | In-memory scan cycle closed-loop execution and 20 P1 live remote AI reasoning tasks via TypeSafe SystemOne endpoint with bounded latency and high confidence (W018–W022, W041, W-G4-LIVE-20). | `PASSED` |
| **G5** | Cryptographic Delivery & Air-Gapped Verification Bundle | Audit signoff, cryptographic checksums, air-gapped bundle (514 deliverables across 331 work packages). | `PASSED` |
| **G6** | Multi-Agent Retrieval Engine & FastMCP Parity | Corpus manifest, dense/sparse retrieval engine, 30 verifiable query evaluations, 5 plan requests, normalized register IDs, held-out off-topic rejection (`NOT FOUND`). | `PASSED` |
| **G7** | Ladder Placement Primitives & Durability Campaign | 10-run campaign rotating NO contact (1000) / NC contact (1001) and coil variants (1002, 37687, 37690, 37691), CFBF control delta >= 2, reopen screenshots with About dialog dismissed and main enabled, negative tests N1–N3. | `PASSED` |
| **G8** | Jev Plan -> Cscape Ladder Edits via G3/G7 Primitives | Autonomous translation of Jev AI planning responses into discrete Cscape ladder logic modifications using proven G3 (IEC variable declaration) and G7 (Ladder editor placement) primitives. Dual-mode execution (offline replay mode vs live mode capped at 30 calls). | `ACTIVE` |
| **G9** | HMI Screen Navigation & Visual Grounding | OmniParser / U2O2 grounding for Cscape HMI screens, screen models & recipes, SVG vector renderer, multi-screen navigation runner, WCAG accessibility remediation. | `OPEN` |
| **G10** | Multi-Rate Closed-Loop Long-Term Soak & Stability | 100,000+ cycle soak, multi-rate stability verification, CLI stress benchmarks, in-process CLI soak profiler, SPC capability profiler. | `OPEN` |
| **G11** | Pre-Commissioning Safety Lockout & Interceptor Audit | Zero-trust physical port lockout (COM1..COM256), Win32 interceptor audit (32827, 33149), physical PLC network lockout. | `OPEN` |
| **G12** | Field Commissioning & Physical PLC Hardware Hand-off | Gated physical commissioning protocol requiring explicit human operator authorization. | `OPEN` |

---

## 2. Gate G8: Exact Acceptance Criteria

### Gate Mandate
Autonomous translation of Jev AI planning responses into discrete Cscape ladder logic modifications using proven G3 (IEC variable declaration / Project Navigator) and G7 (Ladder editor canvas placement, tool selection, tag assignment, rung insertion) primitives.

### Formal Acceptance Criteria

1. **Structured Jev Plan Ingestion**:
   - The campaign engine must ingest structured Jev planning output specifying target variable declarations (IEC name, BOOL type) and ladder rung placement specifications:
     - Contact element: Type (`CONTACT_NO` / `CONTACT_NC`, toolbar cmd `1000` / `1001`) and bound variable/channel tag.
     - Coil element: Variant (`COIL_NO`, `COIL_NC`, `COIL_SET`, `COIL_RESET`, toolbar cmd `1002`, `37687`, `37690`, `37691`) and bound variable/channel tag.
   - Support arbitrary Horner P1 automation tasks with deterministic mapping from Jev decisions to ladder rungs.

2. **Dual-Mode Execution Architecture**:
   - **Offline Replay Mode (`--offline` / default)**:
     - Deterministically replays authentic recorded Jev response fixtures (from the 20 P1 tasks recorded during G4 TypeSafe SystemOne runs).
     - Dispatches **ZERO live network/API calls**.
     - Provides 100% offline reproducible verification with mock or recorded fixtures.
   - **Live Mode (`--live`)**:
     - Interfaces with TypeSafe SystemOne endpoint (`https://api.typesafe.ai/v1/systemone`) using Bearer token authentication.
     - **Strict Hard Cap**: Maximum 30 live API calls (`MAX_LIVE_CALLS = 30`). Calls beyond 30 are unconditionally rejected.
     - **Circuit Breaker**: Halts immediately on 3 consecutive non-200 HTTP responses (`MAX_NON_200_STOPS = 3`).
     - **Execution Constraint**: Live mode is gated and **MUST NOT BE RUN** during offline verification or without explicit operator instruction.

3. **Discrete Cscape Ladder Edits via G3 & G7 Primitives**:
   - **Isolation Guarantee**: All operations must execute exclusively on isolated disposable copies of `work/disposable/p1_base.csp` (`campaign_run_g8_XX.csp`). Baseline `p1_base.csp` SHA-256 (`5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881`) must remain strictly immutable.
   - **G3 Ingestion Primitive**: In-GUI IEC variable declaration in Project Navigator (`SysTreeView32` ID 300, `Add Variable`, modal `CK5TLDlgName` Edit 5004, `WM_COMMAND IDOK`) when new variables are introduced.
   - **G7 Ladder Primitives**:
     - Main ladder editor view resolution (`AfxFrameOrView140su` ID 59649).
     - Rung insertion (`WM_COMMAND 37980`).
     - Vertical toolbar tool activation (contacts 1000/1001, coils 1002/37687/37690/37691).
     - Canvas double-click element placement & tag assignment modal dialog handling (`#32770`, Edit id 1000).
     - Project save (`ID_FILE_SAVE = 57603`) with disk flush verification.

4. **Visual Verification & Modal Dismissal**:
   - Reopen screenshot capture must actively dismiss any delayed `About Cscape` or `#32770` modal dialogs.
   - Main Cscape window must be verified fully enabled (`win32gui.IsWindowEnabled(main_hwnd) == True`) before capturing reopen screenshots.
   - Reopen screenshot must clearly capture the ladder editor canvas with unobstructed contact and coil elements.

5. **CFBF Oracle Readback & 100% Plan Match**:
   - The reopened project file must be validated using an independent CFBF (OLE2 Compound File Binary Format) parser.
   - Verify stream `/Contents` at offset 95 (`main3\x003\x00`) to confirm element count delta >= 2 relative to untouched negative control `p1_base.csp` (base element count == 0).
   - Read back element types and bound tags directly from binary opcode records:
     - `0x00`: `CONTACT_NO`
     - `0x01`: `CONTACT_NC`
     - `0x02`: `COIL_NO`
     - `0x09`: `COIL_NC`
     - `0x0C`: `COIL_SET`
     - `0x0D`: `COIL_RESET`
   - **Assertion**:
     - `readback_contact_type == planned_contact_type`
     - `readback_contact_tag == planned_contact_tag`
     - `readback_coil_type == planned_coil_type`
     - `readback_coil_tag == planned_coil_tag`

6. **Negative Control & Negative Test Suite**:
   - **Negative Control**: Verify untouched `p1_base.csp` has 0 ladder elements and hash `5ab52fee...`.
   - **Test N1 (Invalid Variable Rejection)**: Unbound/invalid variable name (e.g. `1BAD-NAME`) rejected fail-closed with SHA unchanged.
   - **Test N2 (Abort Before Save)**: In-memory ladder placement aborted before save leaves copy SHA unchanged.
   - **Test N3 (Interrupted Save Recovery)**: Interrupted save leaves copy valid CFBF container, reopens cleanly, baseline untouched.

7. **Fail-Closed Hardware Safety Invariants**:
   - Physical communication ports `COM1` through `COM256` blocked unconditionally (`SecurityError`).
   - Companion flashing utilities (`PGMUpdateUtility.exe`, `DfuSeCommand.exe`, `STMFlashLoader.exe`, `WinJTAG.exe`) blocked.
   - CLI download switches (`/d`, `/download`, `/flash`, `/burn`) rejected.
   - Win32 download command IDs `32827` (`ID_PROGRAM_DOWNLOAD`) and `33149` (`ID_CONTROLLER_DOWNLOAD`) intercepted and blocked.
   - Zero Copa-Data Straton K5 dependencies in active code paths.

8. **Verifiable Audit Deliverables**:
   - Execution script: `scripts/g8_campaign.py` (supporting `--offline` and capped `--live`).
   - Negative test script: `scripts/g8_negative_tests.py`.
   - Pytest suite: `tests/test_g8_campaign.py` (offline verification).
   - Summary artifact: `artifacts/G8/g8_campaign_summary.json`.
   - Negative tests evidence: `artifacts/G8/g8_negative_tests_evidence.json`.
   - Visual screenshots: `artifacts/G8/campaign_runs/run_XX_reopen.png`.
   - Status contract compliance: `status: success | failed | blocked | inconclusive`.
