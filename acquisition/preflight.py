import os
import platform
import shutil
from dataclasses import dataclass

_DISK_MARGIN_WINDOWS = 1.10
_DISK_MARGIN_LINUX = 1.20


@dataclass(frozen=True)
class StorageCheckResult:
    ok: bool
    physical_memory_bytes: int
    required_bytes: int
    free_bytes: int
    dump_dir: str
    message: str


def format_bytes(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.2f} KB"
    if size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    return f"{size_bytes / (1024 ** 3):.2f} GB"


def get_physical_memory_bytes():
    system = platform.system()
    if system == "Windows":
        return _physical_memory_windows()
    if system == "Linux":
        return _physical_memory_linux()
    return None


def _physical_memory_windows():
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return None
        return int(stat.ullTotalPhys)
    except Exception:
        return None


def _physical_memory_linux():
    try:
        with open("/proc/meminfo", encoding="utf-8") as meminfo:
            for line in meminfo:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    return kb * 1024
    except Exception:
        pass
    return None


def estimate_required_disk_bytes(os_type, physical_memory_bytes):
    if not physical_memory_bytes:
        return None
    margin = _DISK_MARGIN_LINUX if os_type == "Linux" else _DISK_MARGIN_WINDOWS
    return int(physical_memory_bytes * margin)


def get_free_disk_bytes(path):
    try:
        usage = shutil.disk_usage(path)
        return usage.free
    except Exception:
        return None


def check_storage_for_acquisition(dump_dir, os_type):
    os.makedirs(dump_dir, exist_ok=True)

    physical_memory = get_physical_memory_bytes()
    required = estimate_required_disk_bytes(os_type, physical_memory)
    free = get_free_disk_bytes(dump_dir)

    if physical_memory is None:
        return StorageCheckResult(
            ok=True,
            physical_memory_bytes=0,
            required_bytes=0,
            free_bytes=free or 0,
            dump_dir=dump_dir,
            message=(
                "[WARNING] Could not determine installed RAM. "
                "Ensure the drive has free space roughly equal to system memory before capturing."
            ),
        )

    if required is None or free is None:
        return StorageCheckResult(
            ok=True,
            physical_memory_bytes=physical_memory,
            required_bytes=required or 0,
            free_bytes=free or 0,
            dump_dir=dump_dir,
            message=(
                "[WARNING] Could not verify disk space. "
                f"A full memory dump may need about {format_bytes(physical_memory)} of free space."
            ),
        )

    if free < required:
        shortfall = required - free
        return StorageCheckResult(
            ok=False,
            physical_memory_bytes=physical_memory,
            required_bytes=required,
            free_bytes=free,
            dump_dir=dump_dir,
            message=(
                "[ERROR] Not enough free disk space for a full memory capture. "
                f"Installed RAM: {format_bytes(physical_memory)}. "
                f"Estimated space needed: {format_bytes(required)} "
                f"({int((_DISK_MARGIN_LINUX if os_type == 'Linux' else _DISK_MARGIN_WINDOWS) * 100)}% margin). "
                f"Free on '{dump_dir}': {format_bytes(free)}. "
                f"Short by about {format_bytes(shortfall)}. "
                "Free disk space or choose another output location, then try again."
            ),
        )

    return StorageCheckResult(
        ok=True,
        physical_memory_bytes=physical_memory,
        required_bytes=required,
        free_bytes=free,
        dump_dir=dump_dir,
        message=(
            f"[INFO] Storage check passed. "
            f"RAM: {format_bytes(physical_memory)}, "
            f"required: {format_bytes(required)}, "
            f"free: {format_bytes(free)} on '{dump_dir}'."
        ),
    )
