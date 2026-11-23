# Dependency Inventory & Reusability Analysis: JEV Cscape Agent

This document inventories reusable components, libraries, and optional sub-frameworks evaluated for the **JEV Cscape Agent** project.

---

## 1. Core Automation & Grounding Components

### 1.1 CUA-JEV (Computer-Use Agent for JEV)
- **Role**: High-level action loop, prompt orchestration, step execution watchdog, and fail-closed transaction manager.
- **License**: MIT / Proprietary Internal Policy
- **Version Baseline**: `0.1.0-alpha`
- **Reusability Assessment**: High. Provides structured tool invocation, execution step logging, and the strict 4-state contract (`success | failed | blocked | inconclusive`).
- **Integration Points**: Encapsulated within `src/jev_cscape/agent/`.

### 1.2 pywinauto
- **Role**: Win32 messaging (`WM_COMMAND`), top menu traversal, accelerator dispatch, and Error Check compilation (`ID_PROGRAM_ERRORCHECK = 32826`). UIAutomation 3.0 accessibility tree walking for modal dialogs and dockable panes.
- **License**: BSD 3-Clause License
- **Version Baseline**: `0.6.8+`
- **Status in Environment**: Available for installation in `.venv`; system Python has native Win32 access via `win32gui`/`win32con`.
- **Reusability Assessment**: Essential for non-intrusive GUI automation on `winsta0\Default`.

### 1.3 OmniParser / U2O2 (Optional Vision Grounding)
- **Role**: Screen parsing and visual bounding box grounding for dense GUI controls (e.g. Cscape status bar segments, docking pane splitters, custom MFC owner-drawn controls).
- **License**: MIT / Apache 2.0 (Microsoft)
- **Version Baseline**: `v2.0` / `U2O2-preview`
- **Status in Environment**: Optional dependency. Not currently installed in base runtime to maintain a lightweight, zero-GPU operational footprint.
- **Reusability Assessment**: Recommended as an optional vision backend when UIAutomation tree traversal yields unexposed nested MFC handles.

---

## 2. Forensic & Contract Libraries

| Package | Version Baseline | Installed Version | License | Architectural Role |
| :--- | :---: | :---: | :---: | :--- |
| **pefile** | `2024.8.26` | `2024.8.26` | MIT | Deep PE header inspection, machine type verification (`0x14c`), section parsing, and DLL export forensics. |
| **pydantic** | `>=2.0.0` | `2.13.5` | MIT | Strict 4-state contract schemas, profile models, and operational validation. |
| **pywin32** | `>=306` | `312` | PSF | Direct Win32 API message dispatch, window station inspection, and HWND management. |
| **psutil** | `>=5.9.0` | `7.2.2` | BSD-3-Clause | Process supervision, memory tracking, and 10-minute timeout watchdog enforcement. |
| **pyyaml** | `>=6.0` | `6.0` | MIT | Parsing hardware, Cscape, and agent provider reference profiles. |
| **pytest** | `>=8.0.0` | `9.1.1` | MIT | Deterministic test runner for unit, integration, and security lockout suites. |

---

## 3. Dependency Lock Strategy

All dependencies are recorded in `DEPENDENCIES.lock.json` with version bounds, integrity hashes, and license classifications to ensure deterministic repeatability across air-gapped environments.
