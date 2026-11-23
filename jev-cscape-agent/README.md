# JEV Cscape Agent: Industrial Autonomous Execution & Verification Architecture

> **Root Path**: `C:\HornerAI\jev-cscape-agent\`  
> **Target Host**: Horner APG Cscape 10.2 (Build `10.2.751.4`) on Windows x64  
> **Safety Contract**: Fail-Closed Hardware Lockout | Zero PLC Physical Download  
> **Status Contract**: Strict 4-State (`success | failed | blocked | inconclusive`)  
> **Current Milestone**: Gate G0 (Foundation, Forensics & Environment Inventory)

---

## 1. Executive Summary

**JEV Cscape Agent** (`jev-cscape-agent`) is a dedicated autonomous industrial automation engineering agent designed to interact deterministically with **Horner APG Cscape 10.2** on Windows. 

The architecture is founded upon the **JEV** paradigm (**Jerarquía de Ejecución y Validación** / Execution & Validation Hierarchy):
- **J (Jerarquía Orquestadora)**: Multi-agent coordination, milestone governance, evidence-gated lifecycle across gates G0 through G5.
- **E (Ejecución y Automatización Win32)**: Single GUI Controller operating exclusively on `winsta0\Default`, Win32 messaging, pure IEC 61131-3 Structured Text AST parsing, and CFBF/OLE2 project container manipulation.
- **V (Validación y Seguridad Fail-Closed)**: Deterministic in-memory scan cycle simulation, comprehensive fail-closed safety guards intercepting all physical COM ports, flashing utilities, and download commands.

---

## 2. Strict Safety & Operational Invariants

| Directive | Rule | Enforcement Mechanism |
| :--- | :--- | :--- |
| **Fail-Closed Download Ban** | Physical hardware downloads permanently forbidden | Throws `HardwareLockoutError`; intercepts Win32 commands `32827` and `33149`. |
| **Physical Port Lockout** | `COM1`–`COM256`, `\\.\COM*`, `CAN*`, `USB*`, `JTAG` blocked | Monitored by `SecurityGuard`; zero hardware socket allocation. |
| **Companion Flasher Ban** | `PGMUpdateUtility.exe`, `DfuSeCommand.exe`, `STMFlashLoader.exe`, `WinJTAG.exe` blocked | Execution intercepted and terminated. |
| **Pure Structured Text** | ST POUs reject ladder logic constructs | `ERR_LADDER_FORBIDDEN` triggered if contacts, coils, or rung markers appear. |
| **ST-to-LD Status** | ST→LD conversion within Cscape 10.2 is impossible | Classified as `BLOCKED_NATIVE: DOCUMENT_ONLY` (no menu, no DLL exports). |
| **Single GUI Boundary** | Exactly ONE agent drives Cscape GUI on `winsta0\Default` | Prevents UI deadlocks, clipboard thrashing, and modal focus corruption. |
| **Local-Only Git Tracking** | Git initialized solely for change tracking; zero remotes | No remote repositories configured; push capabilities completely disabled. |
| **4-State Contract** | Tools and subagents strictly return one of four states | `status: "success" \| "failed" \| "blocked" \| "inconclusive"`. No invented statuses. |

---

## 3. Directory Layout

```
C:\HornerAI\jev-cscape-agent\
├── .git/                      # Local-only change tracking (zero remotes)
├── .gitignore                 # Excludes secrets, venvs, and captures
├── README.md                  # Project overview, architecture, and safety rules
├── AGENTS.md                  # Specialized agent roles and behavioral contracts
├── STATUS.md                  # Active progress state and checkpoint ledger
├── NEXT_ACTION.md             # Immediate next steps for session handoff
├── CHANGELOG.md               # Versioned record of engineering milestones
├── THIRD_PARTY_NOTICES.md     # Upstream licenses and notices
├── pyproject.toml             # Python packaging specification
├── DEPENDENCIES.lock.json     # Locked dependency metadata
├── profiles/                  # Hardware, OS, and Cscape reference profiles
│   ├── environment-reference.json # Windows edition, RAM, CPU, interactive session
│   ├── cscape-reference.yaml      # Cscape 10.2 binary, registry, and DPI specs
│   ├── jev-provider.yaml          # Jev agent provider configuration (no secrets)
│   └── supervisor-profile.yaml    # Supervisor watchdog profile (no secrets)
├── docs/                      # Technical references and audits
│   └── DEPENDENCIES.md        # Detailed inventory of reusable libraries (CUA-JEV, pywinauto, OmniParser)
├── ops/                       # Operational tracking and governance
│   ├── backlog.json           # Work package backlog (W001-W030 across G0-G3)
│   ├── gates.json             # Gate states (G0 in_progress, G1-G5 defined)
│   ├── blockers.json          # Active blockers ledger (including credential status)
│   └── decisions.jsonl        # Immutable architectural decision records
├── scripts/                   # Operational and verification scripts
│   ├── bootstrap.ps1          # Idempotent environment bootstrapper
│   └── doctor.ps1             # System health and safety diagnostic doctor
├── src/                       # Main Python codebase
│   └── jev_cscape/            # Core package
├── tests/                     # Deterministic test suites
├── work/                      # Workspace staging and temporary copies
│   └── disposable/            # Disposable sandbox for offline project mutations
└── artifacts/                 # Verifiable logs and cryptographic checkpoints
    ├── checkpoints/           # Milestone checkpoints
    └── logs/                  # Audit execution logs
```

---

## 4. Quickstart

### Step 1: Run Environment Bootstrap
```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
```

### Step 2: Run System & Safety Doctor
```powershell
powershell -ExecutionPolicy Bypass -File scripts\doctor.ps1
```
