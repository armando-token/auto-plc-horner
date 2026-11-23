# W092: Demonstration Guide, Native Project Architecture & Report Reference

## 1. Native Cscape Project Architecture (`p1_base.csp`)

All live Cscape campaigns (`G3`, `G6`, `G7`, `G8`, `G9`, `G10`, `G11`) operate on disposable copies derived from a single canonical native Horner Cscape 10.2 Compound File Binary Format (CFBF / OLE2) baseline project:

- **Canonical Baseline Path**: `work/disposable/p1_base.csp`
- **File Size**: `458,752` bytes
- **Immutable SHA-256 Digest**: `5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881`
- **OLE2 Magic Header**: `D0 CF 11 E0 A1 B1 1A E1`

### Copy-on-Write Isolation Protocol
1. **Pre-Flight Check**: Before every trial, the runner computes the SHA-256 of `work/disposable/p1_base.csp` and asserts it equals `5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881`.
2. **Disposable Working Copy**: The runner copies `p1_base.csp` to an isolated per-trial path (e.g., `artifacts/G11/projects/<trial_id>.csp`).
3. **Live Mutation & Save**: Cscape opens only the disposable copy, applies the requested mutation (`ST_VAR`, `LADDER`, or `HMI`), invokes Error Check (`WM_COMMAND 32826`), and saves via `ID_FILE_SAVE` (`57603`).
4. **Post-Flight Verification**: The runner verifies that:
   - `sha_after != sha_before` on the disposable copy (`sha_mutated == True`),
   - `p1_base.csp` remains untouched (`5ab52fee...`),
   - The saved `.csp` container passes OLE2/CFBF structural integrity checks and reopens cleanly in Cscape.

---

## 2. Running Offline Verifications & Replay Demos (No Live Cscape)

To inspect and verify all gate deliverables without launching Cscape 10.2:

```powershell
# 1. Verify system environment and safety lockouts
python -m jev_cscape.cli doctor

# 2. Evaluate Gate G11 benchmark (270 trials) + endurance (229 trials) results
python scripts/g11_acceptance.py

# 3. Execute Gate G12 offline release verification & closure campaign
python scripts/g12_release_campaign.py

# 4. Run offline unit test suites for G10, G11, and G12
pytest tests/test_g10_campaign.py tests/test_g11_campaign.py tests/test_g12_release.py -v
```

---

## 3. Running Live Cscape Campaigns (Interactive Desktop `winsta0\Default` Only)

> **Warning**: Live runs launch real 32-bit `Cscape.exe` windows on `winsta0\Default` and must be executed exclusively by the operator when no other Cscape instance is active.

```powershell
# Gate G9: 10 Parameterized End-to-End Tasks (10/10 pass)
python scripts/g9_campaign.py

# Gate G10: 28 Negative Fault-Injection & Crash Recovery Scenarios
python scripts/g10_campaign.py --live

# Gate G11: Full Reserved Benchmark (90 unseen tasks x 3 policies = 270 trials)
python scripts/g11_campaign.py --mode full

# Gate G11: Standalone W088 Endurance Worker (e.g. 4-hour soak with checkpoints)
python scripts/g11_campaign.py --endurance-only --endurance-hours 4
```

---

## 4. Interpreting Campaign Reports

Every gate produces machine-readable JSON reports following the strict 4-state contract (`status: "success" | "failed" | "blocked" | "inconclusive"`) plus human-readable acceptance summaries:

| Artifact Path | Description | Key Metrics Verified |
| :--- | :--- | :--- |
| `artifacts/G7/g7_acceptance_summary.json` | Ladder logic 20-task live acceptance | `19/20` (`95.0%`) live pass, `0` errors / `0` warnings |
| `artifacts/G8/g8_acceptance_summary.json` | HMI screen editor 20-task live acceptance | `20/20` (`100.0%`) live pass, `CFBF delta >= 2` |
| `artifacts/G9/g9_campaign_summary.json` | End-to-end 10-task parameterized workflow | `10/10` (`100.0%`) live pass, Task 06 pending guard `blocked` |
| `artifacts/G10/g10_campaign_summary.json` | 28-scenario fault-injection & recovery | `28/28` handled (`16/16` recoverable = `100.0%`, `12/12` unrecoverable = `100.0%`) |
| `artifacts/G11/g11_results.json` | Comparative evaluation & W088 endurance | `270/270` benchmark (`100.0%`), `229/229` 4h endurance (`100.0%`), `$0.175359` total cost |
| `artifacts/G11/g11_acceptance.txt` | Offline G11 acceptance verdict | `OVERALL GATE G11 ACCEPTANCE VERDICT: PASS` |
| `artifacts/G12/g12_release_report.json` | Offline G12 release & closure report | W091–W094 + W098 `success`, `G12_bank: "blocked"` |
| `artifacts/G12/g12_acceptance.txt` | Human-readable G12 offline acceptance | `OVERALL GATE G12 OFFLINE ACCEPTANCE VERDICT: PASS (G12_bank=blocked)` |
