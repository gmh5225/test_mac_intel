"""Measure the CPU time consumed by the benchmark's complete child process trees."""
import atexit
import ctypes
from ctypes import wintypes
import subprocess
import sys
from time import process_time


class BasicAccounting(ctypes.Structure):
    _fields_ = [
        ("total_user", ctypes.c_int64),
        ("total_kernel", ctypes.c_int64),
        ("period_user", ctypes.c_int64),
        ("period_kernel", ctypes.c_int64),
        ("page_faults", wintypes.DWORD),
        ("processes", wintypes.DWORD),
        ("active_processes", wintypes.DWORD),
        ("terminated_processes", wintypes.DWORD),
    ]


kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
kernel.CreateJobObjectW.restype = wintypes.HANDLE
kernel.GetCurrentProcess.argtypes = []
kernel.GetCurrentProcess.restype = wintypes.HANDLE
kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
kernel.AssignProcessToJobObject.restype = wintypes.BOOL
kernel.QueryInformationJobObject.argtypes = [
    wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
kernel.QueryInformationJobObject.restype = wintypes.BOOL
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
kernel.CloseHandle.restype = wintypes.BOOL

job = kernel.CreateJobObjectW(None, None)
if not job:
    raise ctypes.WinError(ctypes.get_last_error())
atexit.register(kernel.CloseHandle, job)
if not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess()):
    raise ctypes.WinError(ctypes.get_last_error())


def accounting():
    info = BasicAccounting()
    # JobObjectBasicAccountingInformation includes active and exited descendants.
    if not kernel.QueryInformationJobObject(job, 1, ctypes.byref(info), ctypes.sizeof(info), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return info


def child_cpu():
    info = accounting()
    return (info.total_user + info.total_kernel) / 10_000_000 - process_time()


if __name__ == "__main__":
    count = accounting().processes
    start = child_cpu()
    spin = "import time\nstart=time.process_time()\nwhile time.process_time()-start<0.2: pass"
    child = "import subprocess, sys; subprocess.run([sys.executable, '-c', sys.argv[1]], check=True)"
    subprocess.run([sys.executable, "-c", child, spin], check=True)
    seconds = child_cpu() - start
    if accounting().processes - count < 2 or seconds < 0.16:
        raise RuntimeError(f"Child and grandchild CPU accounting failed at {seconds:.4f}s")
    print(f"Observed the exited child and grandchild, {seconds:.4f}s CPU")
