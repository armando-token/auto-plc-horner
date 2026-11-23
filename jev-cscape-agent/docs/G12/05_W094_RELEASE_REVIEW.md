# W094: Security, Privacy, Licensing & Cross-Gate Coherence Release Review

**Work Package**: `W094`  
**Automated Verification Script**: [`scripts/g12_release_campaign.py`](../../scripts/g12_release_campaign.py)  
**Machine-Readable Evidence**: [`artifacts/G12/g12_release_report.json`](../../artifacts/G12/g12_release_report.json)

---

## 1. Secrets & Git History Audit (`.env` & `JEV_API_KEY` Never Committed)

The W094 release scanner enforces five deterministic secret-prevention invariants across the repository working tree, Git index (`git ls-files`), and complete Git commit graph (`git log --all --full-history`):

| Check ID | Invariant Description | Verification Method | Measured Result | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| `SEC-01` | `.gitignore` explicitly excludes `.env` and `*.env` | Regex & line check on `.gitignore` (`*.env`, `.env`) | `.gitignore:36:*.env` (`ignored`) | **PASS** |
| `SEC-02` | `.env` is untracked in the Git index | `git ls-files` scan for `.env` | `0` tracked `.env` files (`.env.example` only with placeholder) | **PASS** |
| `SEC-03` | `.env` was **never committed** in Git history | `git log --all --full-history --oneline -- .env "**/.env"` | `0` historical commits touching `.env` | **PASS** |
| `SEC-04` | Zero live API keys (`JEV_API_KEY`, `TYPESAFE_API_KEY`, `sk-`, `Bearer`, `PRIVATE KEY`) in tracked files | Pattern scan over all tracked files in `git ls-files` | `0` live credentials or tokens in tracked files | **PASS** |
| `SEC-05` | Local-only Git repository (zero remote push targets) | `git remote -v` | `0` remotes configured | **PASS** |

---

## 2. Privacy & PII Sanitization Review

- **Endpoint Telemetry**: All HTTP payloads logged in `artifacts/G4/`, `artifacts/G9/`, `artifacts/G10/`, and `artifacts/G11/` record only technical task prompts, HTTP status codes (`200`), request UUIDs (`req_...`), token counts, and USD cost metrics. Authorization headers (`Authorization: Bearer ...` / `X-API-Key`) are never serialized to disk.
- **Host Metadata**: Local workspace paths (`C:\HornerAI\jev-cscape-agent`) and standard Cscape installation paths (`C:\Program Files (x86)\Cscape 10.2\Cscape.exe`) contain no external customer PII, industrial plant IP addresses, or production PLC credentials.

---

## 3. Third-Party Open-Source License Audit

All 16 direct Python dependencies locked in [`requirements.lock.txt`](../../requirements.lock.txt) and [`DEPENDENCIES.lock.json`](../../DEPENDENCIES.lock.json) use permissive open-source licenses (`MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `PSF-2.0`, `Apache-2.0`, `MIT-CMU`). Zero `GPL` / `AGPL` copyleft packages are present:

| Package | Locked Version | License | Compatibility |
| :--- | :--- | :--- | :--- |
| `pydantic` / `pydantic_core` | `2.13.5` / `2.46.5` | `MIT` | Permissive — Commercial & Internal Compatible |
| `pefile` | `2024.8.26` | `MIT` | Permissive — Commercial & Internal Compatible |
| `psutil` | `7.2.2` | `BSD-3-Clause` | Permissive — Commercial & Internal Compatible |
| `pywin32` | `312` | `PSF-2.0` | Permissive — Commercial & Internal Compatible |
| `pywinauto` | `0.6.9` | `BSD-3-Clause` | Permissive — Commercial & Internal Compatible |
| `uiautomation` | `2.0.29` | `Apache-2.0` | Permissive — Commercial & Internal Compatible |
| `comtypes` | `1.4.16` | `MIT` | Permissive — Commercial & Internal Compatible |
| `olefile` | `0.47` | `BSD-2-Clause` | Permissive — Commercial & Internal Compatible |
| `pillow` | `12.3.0` | `MIT-CMU` (HPND) | Permissive — Commercial & Internal Compatible |
| `httpx2` / `httpcore2` | `2.12.0` / `2.12.0` | `BSD-3-Clause` | Permissive — Commercial & Internal Compatible |
| `mcp` | `2.1.1` | `MIT` | Permissive — Commercial & Internal Compatible |
| `anyio` | `4.15.0` | `MIT` | Permissive — Commercial & Internal Compatible |
| `pytest` / `pytest-cov` | `9.1.1` / `7.1.0` | `MIT` | Permissive — Dev/Test Only |
| `pytest-asyncio` | `1.4.0` | `Apache-2.0` | Permissive — Dev/Test Only |

---

## 4. Proprietary Binary Non-Redistribution Verification

- **Git Index Check (`git ls-files`)**: `0` files matching `*.exe`, `*.dll`, `*.msi`, `*.cab`, `*.ocx`, or `*.sys` are tracked in the repository.
- **Git History Check (`git log --all --stat`)**: `0` proprietary Horner APG installers or binaries have ever been committed to the repository.
- **Verification Mechanism**: External Horner APG Cscape 10.2 binaries are verified exclusively in-place at `C:\Program Files (x86)\Cscape 10.2\` via SHA-256 digests in [`DEPENDENCIES.lock.json`](../../DEPENDENCIES.lock.json) and [`scripts/g12_clean_install.ps1`](../../scripts/g12_clean_install.ps1).

---

## 5. Cross-Gate Report Coherence Verification (`G6`–`G11`)

The W094 coherence auditor cross-checks all quantitative claims across gate summary JSONs, acceptance text reports, and documentation:

1. **Canonical Baseline Project SHA-256 Coherence**:
   - `work/disposable/p1_base.csp` (`458,752` bytes) has SHA-256 `5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881` across `G6`, `G7`, `G8`, `G9`, `G10`, `G11`, and `G12`.
2. **Gate G7 (Ladder Logic)**:
   - `artifacts/G7/g7_acceptance_summary.json`: `19/20` (`95.0%`) live pass rate ($\ge 85\%$ threshold).
3. **Gate G8 (HMI Screen Objects)**:
   - `artifacts/G8/g8_campaign_summary.json`: `20/20` (`100.0%`) pass rate.
4. **Gate G9 (End-to-End Parameterized Tasks)**:
   - `artifacts/G9/g9_campaign_summary.json`: `10` tasks total (`8` passed + `1` negative incomplete handled + `1` Task 06 destructive confirmation guard `pending`, `0` failed).
5. **Gate G10 (Negative Fault Injection & Recovery)**:
   - `artifacts/G10/g10_campaign_summary.json`: `28/28` scenarios handled (`16/16 = 100.0%` recoverable $\ge 90\%$ threshold; `6/6` abstain matched; `6/6` pause matched; `0` out-of-scope writes, `0` blind retries, `0` false completions).
6. **Gate G11 (Comparative Benchmark & W088 Endurance)**:
   - `artifacts/G11/g11_results.json` & `artifacts/G11/g11_acceptance.txt`:
     - Benchmark (`W084`–`W087`): `270` scheduled trials (`269/270` passed in initial full run; single `LADDER_19__jev_full` healed in commit `f218227` and verified `PASS` in W088; `270/270` on-disk `.csp` files verified with `sha_mutated=270/270` and `ole_cfbf_reopen_ok=270/270`).
     - Endurance (`W088`): `229/229` (`100.0%`) passed over a **4.0-hour (`14,415.93s`) live run** (`--endurance-only --endurance-hours 4`), with `22` controlled restarts, `0` duplicate trial IDs, `0` corruptions (`229/229` `sha_mutated`, `229/229` `reopen_ok`, `229/229` `compile_clean`).
     - Combined Live Totals (`499` trials): `333` real API calls (`180` benchmark + `153` endurance), `340,932` tokens (`184,414` + `156,518`), `$0.765440` USD cost (`$0.414160` + `$0.351280`).
     - The 4.0-hour endurance duration (rather than 24 hours) is transparently disclosed across `artifacts/G11/g11_acceptance.txt`, `docs/G12/03_LIMITATIONS_AND_STOP_RECOVER.md`, `docs/G12/06_W098_CLOSURE_AND_V2_BACKLOG.md`, and `artifacts/G12/g12_release_report.json`.
