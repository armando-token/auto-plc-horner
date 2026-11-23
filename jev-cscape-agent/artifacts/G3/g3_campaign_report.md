# Gate G3 Campaign & Edit Roundtrip Verification Report

- **Generated (UTC)**: `2026-10-10T01:01:20.814106+00:00`
- **Overall Status**: `SUCCESS (10/10 PASS)`
- **Total Runs Executed**: `10`
- **Passed Runs**: `10`
- **Failed Runs**: `0`
- **Baseline `p1_base.csp`**: `INTACT` (`5ab52feeff31fda15301cebf1498dddb25167f8ea8a3640185d511600b5f2881`)
- **Baseline `test_sandbox.csp`**: `INTACT` (`25112eebdae56a77a97c0e37536eab3975a38ae3815b3850b9a8dfa12bb20592`)

## 1. Per-Run Audit Evidence Matrix

| Run | Value | Status | Reopen Count | CFBF Oracle Status | CFBF Matched Record | Shared IEC Read Method |
| :---: | :---: | :---: | :---: | :---: | :--- | :--- |
| `01` | `G3_TEST_VAR_01` | `SUCCESS` | `24` | `PASSED` | `/V,G,BOOL(0)[0],0,G3_TEST_VAR_01` | `Frame WM_COMMAND 0xE12A/0xE122 + Clipboard (HWND 0x1190608, class 'W5EditST')` |
| `02` | `G3_TEST_VAR_02` | `SUCCESS` | `24` | `PASSED` | `/V,G,BOOL(0)[0],0,G3_TEST_VAR_02` | `Frame WM_COMMAND 0xE12A/0xE122 + Clipboard (HWND 0x470188, class 'W5EditST')` |
| `03` | `G3_TEST_VAR_03` | `SUCCESS` | `24` | `PASSED` | `/V,G,BOOL(0)[0],0,G3_TEST_VAR_03` | `Frame WM_COMMAND 0xE12A/0xE122 + Clipboard (HWND 0xd505d0, class 'W5EditST')` |
| `04` | `G3_TEST_VAR_01` | `SUCCESS` | `24` | `PASSED` | `/V,G,BOOL(0)[0],0,G3_TEST_VAR_01` | `Frame WM_COMMAND 0xE12A/0xE122 + Clipboard (HWND 0x5230378, class 'W5EditST')` |
| `05` | `G3_TEST_VAR_02` | `SUCCESS` | `24` | `PASSED` | `/V,G,BOOL(0)[0],0,G3_TEST_VAR_02` | `Frame WM_COMMAND 0xE12A/0xE122 + Clipboard (HWND 0x40603f0, class 'W5EditST')` |
| `06` | `G3_TEST_VAR_03` | `SUCCESS` | `24` | `PASSED` | `/V,G,BOOL(0)[0],0,G3_TEST_VAR_03` | `Frame WM_COMMAND 0xE12A/0xE122 + Clipboard (HWND 0x2310012, class 'W5EditST')` |
| `07` | `G3_TEST_VAR_01` | `SUCCESS` | `24` | `PASSED` | `/V,G,BOOL(0)[0],0,G3_TEST_VAR_01` | `Frame WM_COMMAND 0xE12A/0xE122 + Clipboard (HWND 0x422008e, class 'W5EditST')` |
| `08` | `G3_TEST_VAR_02` | `SUCCESS` | `24` | `PASSED` | `/V,G,BOOL(0)[0],0,G3_TEST_VAR_02` | `Frame WM_COMMAND 0xE12A/0xE122 + Clipboard (HWND 0x19f0532, class 'W5EditST')` |
| `09` | `G3_TEST_VAR_03` | `SUCCESS` | `24` | `PASSED` | `/V,G,BOOL(0)[0],0,G3_TEST_VAR_03` | `Frame WM_COMMAND 0xE12A/0xE122 + Clipboard (HWND 0x2940522, class 'W5EditST')` |
| `10` | `G3_TEST_VAR_01` | `SUCCESS` | `24` | `PASSED` | `/V,G,BOOL(0)[0],0,G3_TEST_VAR_01` | `Frame WM_COMMAND 0xE12A/0xE122 + Clipboard (HWND 0x1c305dc, class 'W5EditST')` |

## 2. Invariant Sign-Off

- [x] **Zero Keystrokes into IEC Editor**: All reads used pure frame `WM_COMMAND` `0xE12A` (Select All) and `0xE122` (Copy) via Windows clipboard.
- [x] **Independent CFBF Disk Oracle**: Evaluated `/V,` records in the CFBF `Contents` stream for every run, asserting `BOOL` type independently of the GUI.
- [x] **Completeness & Stability**: Every IEC editor read verified headers (`VAR`), termination (`END_VAR`), declaration count (`24`), and required 2 consecutive identical reads.
- [x] **Reopen Close Without Saving**: On reopen, save prompts answered `No` (`IDNO=7`), verifying file SHA was preserved across reopening.
- [x] **Baseline Project Immutability**: `p1_base.csp` and `test_sandbox.csp` remained completely unmodified across all runs.
