"""Keep Cscape live and visible on winsta0\\Default."""

import ctypes
import os
import subprocess
import sys
import time
import winreg

sys.path.insert(0, os.path.abspath("src"))
from jev_cscape.automation.launcher import CscapeLauncher

CSCAPE_EXE = r"C:\Program Files (x86)\Cscape 10.2\Cscape.exe"
CSCAPE_DIR = r"C:\Program Files (x86)\Cscape 10.2"
PROJECT_PATH = r"C:\HornerAI\jev-cscape-agent\work\disposable\test_sandbox.csp"

launcher = CscapeLauncher()
res = launcher.launch(project_path=PROJECT_PATH, timeout=30.0)
print(f"Launch result: {res.status}: {res.details}")

if res.data and "main_window" in res.data:
    print(f"HWND: {res.data['main_window'].get('hwnd_hex')}")

# Keep alive loop
try:
    while True:
        time.sleep(10)
except KeyboardInterrupt:
    pass
