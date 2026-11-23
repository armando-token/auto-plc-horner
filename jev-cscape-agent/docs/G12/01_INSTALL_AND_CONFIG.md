# W091 & W092: Clean Installation, Lockfile & Configuration Guide

## 1. Non-Redistribution Policy for Proprietary Binaries

This repository **never redistributes** proprietary Horner APG installers, executables (`.exe`), or dynamic link libraries (`.dll`). Operators must install Horner APG **Cscape 10.2 (Build 10.2.751.4)** independently from official Horner Electric media into `C:\Program Files (x86)\Cscape 10.2\`.

To guarantee binary compatibility before running any live automation, verify the local installation against the cryptographic SHA-256 ledger recorded in [`DEPENDENCIES.lock.json`](../../DEPENDENCIES.lock.json):

| Binary File | Size (Bytes) | Expected SHA-256 Digest | Role / Policy |
| :--- | ---: | :--- | :--- |
| `Cscape.exe` | `17,663,488` | `4b82560db103b4f26a9163bee3ae29439712c1c69ccaac11d0e898e51dcde405` | Primary Cscape 10.2 x86 Host (`0x14c`) |
| `W5EditST.dll` | `4,174,544` | `67c7aca5634fb706a0f3f6637de282d7b5e52f7d451c78996d27b4979043e745` | IEC 61131-3 ST Editor & Dialog 108 |
| `W5EditLD.dll` | `5,082,832` | `45dd5b31379173feabf3801cbf1fc98e9f1e19c9a74ca76c28f4814196bb41ec` | IEC / Advanced Ladder Editor |
| `K5Cmp.dll` | `5,231,824` | `423f4005626dbe0a6f1a04f6871fd5f4c5e726d614ec636f9a54af2027f88b2e` | IEC 61131-3 Compiler Engine |
| `K5MW.dll` | `4,033,232` | `e62ca003be9ff8a7a84f2dd3e48318094341fd3055497fd6e46e4a61f25362ba` | Middleware & Project Tree Engine |
| `K5CBM.dll` | `3,401,424` | `0c9b24926e5db1a9d807c9572e2bacc91b99d36bdd0425379620b7e04f7bb801` | Control Block Manager |
| `PGMUpdateUtility.exe` | `63,488` | `46c98926688b7438f99be213f09f245c6e0f1d867e8739758d74c08887b62238` | **HARD LOCKED OUT** (`G0`/`G11`) |
| `DfuSeCommand.exe` | `27,648` | `f60c79d21fa1a28cfe40719501fc580f9f5bf31ad175f3b301365707bb1e7ef8` | **HARD LOCKED OUT** (`G0`/`G11`) |
| `STMFlashLoader.exe` | `41,472` | `ba3a75c8870c5746b3f4defadc30a32e8c63e3aa605917485f4cd2b7808aad6d` | **HARD LOCKED OUT** (`G0`/`G11`) |
| `WinJTAG.exe` | `249,856` | `dca5a3ea52ef656f976caf88d6f0a340049c026036c4dbb4ede9ca8b0c6428c9` | **HARD LOCKED OUT** (`G0`/`G11`) |

---

## 2. Clean Installation Procedure (W091)

### Prerequisites
- **OS**: Windows 11 x64 with interactive desktop session (`winsta0\Default` required only for live GUI runs; offline checks run headless).
- **Python**: Python `3.12.10` (64-bit AMD64).

### Step-by-Step Clean Install
```powershell
# Step 1: Run the automated clean-install and checksum verification script
powershell -ExecutionPolicy Bypass -File scripts/g12_clean_install.ps1 -VenvDir .venv

# Step 2: Or run in read-only verification mode on an existing environment
powershell -ExecutionPolicy Bypass -File scripts/g12_clean_install.ps1 -VerifyOnly
```

### Manual Virtual Environment Setup
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.lock.txt
pip install --no-deps -e .
```

---

## 3. Environment & API Key Configuration (W092)

Live reasoning campaigns (`G4`, `G9`, `G10`, `G11`) communicate with the remote TypeSafe SystemOne endpoint (`https://api.typesafe.ai/v1/systemone`). Credentials are loaded from a local `.env` file that is strictly excluded from version control by `.gitignore` (`*.env`).

```powershell
# Copy the sanitized template to .env
Copy-Item .env.example .env
```

Edit `.env` locally and set:
```ini
JEV_API_KEY=your_typesafe_jev_api_key_here
JEV_API_URL=https://api.typesafe.ai/v1/systemone
JEV_MODEL=jev-latest
CSCAPE_EXE_PATH="C:\Program Files (x86)\Cscape 10.2\Cscape.exe"
CSCAPE_BASELINE_CSP="work/disposable/p1_base.csp"
JEV_HARDWARE_LOCKOUT=1
JEV_G12_BANK_STATUS=blocked
```

> **Security Mandate (W094)**: Never commit `.env` or pass raw API keys on the command line. `scripts/g12_release_campaign.py` scans both the working index (`git ls-files`) and full commit history (`git log --all --full-history -- .env`) to verify zero secret leakage.

---

## 4. Real Clean-Install Verification Evidence (`W091`)

A complete offline clean-install verification was executed by cloning `C:\HornerAI\jev-cscape-agent` at `HEAD` into a fresh directory `C:\HornerAI\g12_clean_install` with **no `.env` copied** (`.env Present: False`) and zero Cscape GUI invocation. The full execution transcript is archived in [`artifacts/G12/w091_clean_install_run.log`](../../artifacts/G12/w091_clean_install_run.log).

| Verification Item | Recorded Value / Hash | Verdict |
| :--- | :--- | :--- |
| **Clean Clone Path** | `C:\HornerAI\g12_clean_install` (`.env` absent: `True`, Git remotes: `0`) | **PASS** |
| **Virtual Environment Python** | `C:\HornerAI\g12_clean_install\.venv\Scripts\python.exe` — **Python `3.12.10` (`64bit`)** | **PASS** |
| **`requirements.lock.txt` Raw SHA-256** | `aa5a33979fb0d34dc311d588ef0f7fa4a66a976a9ce0157435012df6316e7be2` (`46` pinned packages) | **PASS** |
| **`requirements.lock.txt` Normalized SHA-256** | `0bd63d6eab27f817e7c2b060a8c3f9fe4a7093836c87e544688e341ea0a3121f` (`46` packages) | **PASS** |
| **`.venv` `pip freeze` Normalized SHA-256** | `0bd63d6eab27f817e7c2b060a8c3f9fe4a7093836c87e544688e341ea0a3121f` (`46` packages, exact match `True`) | **PASS** |
| **W091 Script (`scripts/g12_clean_install.ps1`)** | `16/16` direct locked packages, `p1_base.csp` SHA-256 verified, `6/6` Cscape 10.2 PE checksums verified | **PASS** |
| **G11 Offline Verifier (`scripts/g11_acceptance.py`)** | `270/270` benchmark trials (`90/90` per policy), `229/229` W088 endurance trials (`4.0005h`), `0` corruptions | **PASS** |
| **G12 Offline Verifier (`scripts/g12_release_campaign.py`)** | `W091`–`W094` + `W098` `SUCCESS`, `W095`–`W097` `BLOCKED` (`G12_bank=blocked`), `14/14` W094 checks passed | **PASS** |
| **Full Offline Pytest Suite (`pytest -q`)** | **`15,109 passed`, `0 failed`** (`15,109 / 15,109` items, exit code `0`, zero live Cscape launches) | **PASS** |
