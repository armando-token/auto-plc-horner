"""Diagnose Windows Session, Integrity Level, and Desktop Architecture."""

import ctypes
from ctypes import wintypes
from typing import Optional
import os
import sys
import time
import psutil

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32
user32 = ctypes.windll.user32

kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]

advapi32.GetTokenInformation.restype = wintypes.BOOL
advapi32.GetTokenInformation.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

advapi32.GetSidSubAuthorityCount.restype = ctypes.c_void_p
advapi32.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]

advapi32.GetSidSubAuthority.restype = ctypes.c_void_p
advapi32.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]

user32.OpenInputDesktop.restype = ctypes.c_void_p
user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

user32.GetThreadDesktop.restype = ctypes.c_void_p
user32.GetThreadDesktop.argtypes = [wintypes.DWORD]

user32.GetProcessWindowStation.restype = ctypes.c_void_p
user32.GetProcessWindowStation.argtypes = []

user32.GetUserObjectInformationW.restype = wintypes.BOOL
user32.GetUserObjectInformationW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

def get_session_id(pid: int) -> int:
    sess = wintypes.DWORD()
    if kernel32.ProcessIdToSessionId(pid, ctypes.byref(sess)):
        return sess.value
    return -1

def get_integrity_level(pid: int) -> str:
    h_proc = kernel32.OpenProcess(0x0400, False, pid)
    if not h_proc:
        return f"OpenProcess failed: {kernel32.GetLastError()}"
    h_tok = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(h_proc, 0x0008, ctypes.byref(h_tok)):
        kernel32.CloseHandle(h_proc)
        return f"OpenProcessToken failed: {kernel32.GetLastError()}"
    
    cb_needed = wintypes.DWORD()
    advapi32.GetTokenInformation(h_tok.value, 25, None, 0, ctypes.byref(cb_needed))
    buf = ctypes.create_string_buffer(cb_needed.value)
    if advapi32.GetTokenInformation(h_tok.value, 25, buf, cb_needed.value, ctypes.byref(cb_needed)):
        p_sid_and_attr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))
        p_sid = p_sid_and_attr[0]
        p_subauth_count = advapi32.GetSidSubAuthorityCount(p_sid)
        subauth_count = ctypes.cast(p_subauth_count, ctypes.POINTER(ctypes.c_ubyte))[0]
        p_rid = advapi32.GetSidSubAuthority(p_sid, subauth_count - 1)
        rid = ctypes.cast(p_rid, ctypes.POINTER(wintypes.DWORD))[0]
        kernel32.CloseHandle(h_tok.value)
        kernel32.CloseHandle(h_proc)
        levels = {
            0x0000: "Untrusted (0x0000)",
            0x1000: "Low (0x1000)",
            0x2000: "Medium (0x2000)",
            0x2100: "Medium-Plus (0x2100)",
            0x3000: "High (0x3000)",
            0x4000: "System (0x4000)",
            0x5000: "Protected (0x5000)"
        }
        return levels.get(rid, f"Custom (0x{rid:04X})")
    kernel32.CloseHandle(h_tok.value)
    kernel32.CloseHandle(h_proc)
    return f"GetTokenInformation failed: {kernel32.GetLastError()}"

def get_desktop_name(h_desk: Optional[int]) -> str:
    if not h_desk:
        return "None"
    buf = ctypes.create_unicode_buffer(256)
    needed = wintypes.DWORD()
    if user32.GetUserObjectInformationW(h_desk, 2, ctypes.byref(buf), 256, ctypes.byref(needed)):
        return buf.value
    return f"Error: {kernel32.GetLastError()}"

def get_winsta_name(h_winsta: Optional[int]) -> str:
    if not h_winsta:
        return "None"
    buf = ctypes.create_unicode_buffer(256)
    needed = wintypes.DWORD()
    if user32.GetUserObjectInformationW(h_winsta, 2, ctypes.byref(buf), 256, ctypes.byref(needed)):
        return buf.value
    return f"Error: {kernel32.GetLastError()}"

def main():
    py_pid = os.getpid()
    py_sess = get_session_id(py_pid)
    py_il = get_integrity_level(py_pid)
    py_winsta = user32.GetProcessWindowStation()
    py_winsta_name = get_winsta_name(py_winsta)
    py_desk = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
    py_desk_name = get_desktop_name(py_desk)

    print("================================================================================")
    print("  INPUT BLOCK DIAGNOSTIC: SESSION, INTEGRITY LEVEL, AND DESKTOP FORENSICS")
    print("================================================================================")
    print("PYTHON RUNTIME:")
    print(f"  PID:              {py_pid}")
    print(f"  Session ID:       {py_sess}")
    print(f"  Integrity Level:  {py_il}")
    print(f"  Window Station:   {hex(py_winsta) if py_winsta else 'None'} ({py_winsta_name})")
    print(f"  Thread Desktop:   {hex(py_desk) if py_desk else 'None'} ({py_desk_name})")

    # OpenInputDesktop
    h_input = user32.OpenInputDesktop(0, False, 0x01FF)
    err = kernel32.GetLastError()
    input_name = get_desktop_name(h_input) if h_input else "None"
    print("\nOPEN INPUT DESKTOP:")
    print(f"  Handle:           {hex(h_input) if h_input else 'NULL'}")
    print(f"  Desktop Name:     {input_name}")
    print(f"  GetLastError():   {err}")

    # Launch Cscape to inspect it
    exe_path = r"C:\Program Files (x86)\Cscape 10.2\Cscape.exe"
    proc = psutil.Popen([exe_path], cwd=os.path.dirname(exe_path))
    time.sleep(6.0)

    cs_pid = proc.pid
    cs_sess = get_session_id(cs_pid)
    cs_il = get_integrity_level(cs_pid)

    cs_threads = proc.threads()
    cs_tid = cs_threads[0].id if cs_threads else None
    cs_desk = user32.GetThreadDesktop(cs_tid) if cs_tid else None
    cs_desk_name = get_desktop_name(cs_desk) if cs_desk else "Unknown"

    print("\nCSCAPE 10.2 PROCESS:")
    print(f"  PID:              {cs_pid}")
    print(f"  Session ID:       {cs_sess}")
    print(f"  Integrity Level:  {cs_il}")
    print(f"  Main Thread ID:   {cs_tid}")
    print(f"  Thread Desktop:   {hex(cs_desk) if cs_desk else 'None'} ({cs_desk_name})")

    proc.kill()
    print("================================================================================")

if __name__ == "__main__":
    main()
