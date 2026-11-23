# W092: Engineering Limitations, Stop Procedures & Crash Recovery

## 1. Documented System & Campaign Limitations

In accordance with the Gate G1/G12 honesty mandate, all architectural boundaries, platform limitations, and campaign scope constraints are explicitly documented below:

### L1. W088 Endurance Horizon: 4.0-Hour Live Execution vs. 24-Hour Design Target
- **Design Target**: The initial W088 specification contemplated an up-to-24-hour endurance worker soak.
- **Actual Certified Live Execution**: W088 was executed live using `--endurance-only --endurance-hours 4` for **4.004 hours (`14,415.93` seconds)** (`2026-10-16T03:35:04Z` to `2026-10-16T07:35:20Z`).
- **Measured Outcome**: `229 / 229` trials succeeded (`100.0%` success rate, `0` failures, `0` corruptions, `22` controlled worker restarts every 10 trials, `229/229` SHA-256 mutations verified, `229/229` clean reopens, `229/229` clean compiles).
- **Rationale & Residual Risk**: While the 4-hour live run validated 22 full worker lifecycle restarts and 229 consecutive live Cscape compile-and-save cycles with zero handle leaks or CFBF corruptions, 24-hour multi-day OS thermal/desktop lock endurance remains a v2 backlog item (`V2-P2`).

### L2. Optional Physical PLC Hardware Bench (`G12_bank = blocked`)
- **Status**: `blocked` (`W095`, `W096`, `W097` not executed on physical hardware).
- **Reason**: No physical Horner OCS controller is connected to the host, and the fail-closed hardware safety barrier (`CommissioningGuard`, `ops/commissioning_lockout.json`, `POL-G12-COMMISSIONING-LOCKOUT`) permanently blocks `COM1`–`COM256`, `USB*`, `CAN*`, `JTAG`, companion flashing utilities (`PGMUpdateUtility.exe`, `DfuSeCommand.exe`, `STMFlashLoader.exe`, `WinJTAG.exe`), and Win32 download command IDs (`32827` `ID_PROGRAM_DOWNLOAD`, `33149` `ID_CONTROLLER_DOWNLOAD`).

### L3. No Native ST-to-Ladder Conversion in Cscape 10.2 (`BLOCKED_NATIVE: DOCUMENT_ONLY`)
- **Forensic Evidence (`G0`)**: PE export table inspection of `Cscape.exe`, `W5EditST.dll`, `W5EditLD.dll`, `K5Cmp.dll`, `K5MW.dll`, and `K5CBM.dll` confirmed zero native routines for converting IEC 61131-3 Structured Text POUs into Ladder Logic rungs inside Cscape 10.2.
- **Enforcement**: Requests for automatic in-GUI ST-to-Ladder translation fail closed with `status: "blocked"` and `error_code: "BLOCKED_NATIVE"`.

### L4. `W5EditST` Text Buffer Opacity (32-bit Custom Control)
- **Constraint**: Cscape's Structured Text editor (`W5EditST.dll`) renders code on an owner-drawn GDI canvas and returns `0` characters to Win32 `WM_GETTEXT` and UIAutomation `TextPattern` queries.
- **Mitigation**: Variable declarations use deterministic Dialog `108` (`SysListView32` ID `1011`) grid editing (`G3`/`G6`), and semantic verification relies on Compiler Output ListBox (`ID 372` inside Output Window `ID 45011` via `WM_COMMAND 32826`) plus CFBF `.csp` binary stream inspection.

### L5. Single Interactive GUI Session Requirement (`winsta0\Default`)
- **Constraint**: Because Cscape 10.2 is a 32-bit MFC SDI/MDI desktop application without a headless CLI compiler flag, exactly **one** automation worker may own the Cscape `HWND` on `winsta0\Default` at any time. Parallel execution is restricted to offline analysis, retrieval, and test verification; live Cscape trials execute sequentially under an exclusive mutex lock.

---

## 2. Emergency Stop Procedure

If a live Cscape campaign (`g9_campaign.py`, `g10_campaign.py`, `g11_campaign.py`) must be halted immediately:

### Graceful Stop (Recommended)
Press `Ctrl+C` once in the PowerShell terminal running the campaign. The campaign signal handler traps `KeyboardInterrupt`, flushes the current trial checkpoint to `artifacts/G11/w088_checkpoint.json` (or gate log), closes any modal dialogs, terminates the active `Cscape.exe` child process cleanly, and verifies that `work/disposable/p1_base.csp` is unmodified.

### Immediate Emergency Kill (PowerShell)
If the GUI desktop is unresponsive or a modal dialog blocks input, run the following command in an elevated or separate PowerShell window:

```powershell
# Terminate any stray Cscape.exe automation processes and release file handles
Get-Process -Name "Cscape" -ErrorAction SilentlyContinue | Stop-Process -Force
```

> **Safety Note**: Never terminate companion flashers because they are never launched (`PGMUpdateUtility.exe`, `DfuSeCommand.exe`, `STMFlashLoader.exe`, `WinJTAG.exe` are blocked before process creation).

---

## 3. Post-Crash Recovery & Integrity Verification

After any abnormal termination or forced stop (`W079` / `W080` / `W081` verified in Gate G10 with `16/16` `100.0%` recoverable fault pass rate):

```powershell
# 1. Verify no zombie Cscape processes remain
Get-Process -Name "Cscape" -ErrorAction SilentlyContinue

# 2. Verify canonical baseline project integrity (must match 5ab52fee...)
powershell -ExecutionPolicy Bypass -File scripts/g12_clean_install.ps1 -VerifyOnly

# 3. Inspect or resume from the W088 endurance checkpoint
Get-Content artifacts/G11/w088_checkpoint.json | ConvertFrom-Json | Select-Object status, completed_count, failed_count, worker_restarts
```

### Resuming an Interrupted Endurance Run
`scripts/g11_campaign.py` persists atomic JSON checkpoints (`artifacts/G11/w088_checkpoint.json`) after every trial and performs a controlled Cscape process recycle every 10 trials (`restart_interval_trials = 10`). Re-running `--endurance-only` automatically loads the checkpoint or starts a clean bounded window while preserving all prior benchmark metrics in `artifacts/G11/g11_results.json`.
