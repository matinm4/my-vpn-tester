"""تضمین اینکه هیچ پروسه‌ی xray پس از مرگ برنامه زنده نماند.

روی ویندوز همه‌ی فرزندها به یک Job Object با پرچم KILL_ON_JOB_CLOSE بسته
می‌شوند: اگر پروسه‌ی پدر به هر دلیلی بمیرد — حتی kill سخت یا قطع برق نرم —
خود ویندوز کل مجموعه را می‌بندد. بدون این، یک اجرای نصفه‌کاره ده‌ها پروسه‌ی
یتیم روی سیستم جا می‌گذارد.

اگر هر بخشی از این مسیر در دسترس نباشد، ماژول بی‌صدا غیرفعال می‌شود و رفتار
برنامه دقیقاً مثل قبل می‌ماند.
"""

from __future__ import annotations

import os
import subprocess
import threading
from typing import Optional

_IS_WINDOWS = os.name == "nt"

_JobObjectExtendedLimitInformation = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

_lock = threading.Lock()
_job_handle: Optional[int] = None
_initialised = False
_available = False


def _build_job() -> Optional[int]:
    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
    ]

    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        return None

    info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    ok = kernel32.SetInformationJobObject(
        handle, _JobObjectExtendedLimitInformation,
        ctypes.byref(info), ctypes.sizeof(info),
    )
    if not ok:
        kernel32.CloseHandle(handle)
        return None
    return handle


def _ensure_job() -> None:
    global _job_handle, _initialised, _available
    if _initialised:
        return
    _initialised = True
    if not _IS_WINDOWS:
        return
    try:
        _job_handle = _build_job()
        _available = _job_handle is not None
    except Exception:  # noqa: BLE001 - نبود Job Object نباید مانع اجرا شود
        _job_handle = None
        _available = False


def adopt(proc: subprocess.Popen) -> bool:
    """پروسه را به Job Object می‌سپارد. خروجی: موفق بود یا نه."""
    if not _IS_WINDOWS:
        return False
    with _lock:
        _ensure_job()
        if not _available or _job_handle is None:
            return False
        try:
            import ctypes

            handle = getattr(proc, "_handle", None)
            if handle is None:
                return False
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            return bool(kernel32.AssignProcessToJobObject(_job_handle, int(handle)))
        except Exception:  # noqa: BLE001
            return False


def is_active() -> bool:
    with _lock:
        _ensure_job()
        return _available
