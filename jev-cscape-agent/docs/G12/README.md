# Gate G12 Technical Delivery Package (`docs/G12/`)

**Gate**: `G12` — *Entrega técnica, demostración y banco opcional*  
**Work Packages Covered**: `W091`, `W092`, `W093`, `W094`, `W098` (`W095`–`W097` Hardware Bench: `G12_bank=blocked`)  
**Target Platform**: Windows 11 x64 (`winsta0\Default`), Python `3.12.10` (64-bit), Horner APG Cscape `10.2` (Build `10.2.751.4`, 32-bit x86 PE)  
**Hardware Commissioning Status**: `blocked` (`POL-G12-COMMISSIONING-LOCKOUT` / `FAIL_CLOSED_HARDWARE_LOCKOUT`, zero physical PLCs connected)

---

## Package Index

| Document | Work Package | Scope |
| :--- | :--- | :--- |
| [`01_INSTALL_AND_CONFIG.md`](01_INSTALL_AND_CONFIG.md) | **W091 / W092** | Clean installation (`scripts/g12_clean_install.ps1`), pinned lockfiles (`requirements.lock.txt`, `DEPENDENCIES.lock.json`), `.env` configuration from `.env.example`, and non-redistributed Cscape 10.2 binary SHA-256 checksum verification. |
| [`02_DEMO_AND_NATIVE_PROJECT.md`](02_DEMO_AND_NATIVE_PROJECT.md) | **W092** | Offline & live demonstration workflows, native Cscape project architecture (`work/disposable/p1_base.csp`), copy-on-write isolation, and JSON/text acceptance report structure. |
| [`03_LIMITATIONS_AND_STOP_RECOVER.md`](03_LIMITATIONS_AND_STOP_RECOVER.md) | **W092** | Honest engineering limitations (including 4.0h W088 endurance run vs 24h design horizon, `W5EditST` text opacity, ST-to-Ladder `BLOCKED_NATIVE`, `G12_bank=blocked`), emergency stop, crash recovery, and checkpoint resumption. |
| [`04_HORNER_TECHNICAL_DOSSIER.md`](04_HORNER_TECHNICAL_DOSSIER.md) | **W093** | JEV 3-layer architecture diagram (`J-Layer`, `E-Layer`, `V-Layer`), certified capability tables (`G0`–`G11`), complete G0–G11 artifact evidence index with SHA-256 digests, and 6 technical collaboration questions for Horner APG engineering. |
| [`05_W094_RELEASE_REVIEW.md`](05_W094_RELEASE_REVIEW.md) | **W094** | Automated & manual release security review: zero secrets in git index/history (`.env` / `JEV_API_KEY` never committed), PII/privacy audit, open-source license matrix, zero proprietary binary redistribution, and G7–G11 cross-gate report coherence. |
| [`06_W098_CLOSURE_AND_V2_BACKLOG.md`](06_W098_CLOSURE_AND_V2_BACKLOG.md) | **W098** | Gate G12 offline acceptance closure (`G12_bank=blocked` for `W095`–`W097`), final gate ledger (`G0`–`G12`), and prioritized v2 engineering backlog (`P1`–`P6`). |

---

## Quick Verification Commands (Offline, Zero Live Cscape)

```powershell
# 1. Verify environment, lockfiles, baseline project SHA-256, and Cscape 10.2 PE checksums
powershell -ExecutionPolicy Bypass -File scripts/g12_clean_install.ps1 -VerifyOnly

# 2. Run Gate G11 offline acceptance report generator
python scripts/g11_acceptance.py

# 3. Run Gate G12 offline release verification & acceptance suite (W091-W094 + W098)
python scripts/g12_release_campaign.py

# 4. Run Gate G12 unit tests
pytest tests/test_g12_release.py -v
```
