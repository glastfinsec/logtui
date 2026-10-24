"""OS and tool detection."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess


def detect_os() -> str:
    s = platform.system().lower()
    if s == "darwin":
        return "macos"
    if s == "windows":
        return "windows"
    return "linux"


def detect_os_version() -> str:
    try:
        if detect_os() == "windows":
            return platform.version()
        if detect_os() == "macos":
            return platform.mac_ver()[0] or platform.release()
        # linux
        # try /etc/os-release
        try:
            with open("/etc/os-release", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.strip().split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return platform.release()
    except Exception:
        return platform.release()


def detect_init() -> str:
    osname = detect_os()
    if osname == "windows":
        return "windows_eventlog"
    if osname == "macos":
        return "launchd"
    # linux: check systemd
    if shutil.which("systemctl") and os.path.exists("/run/systemd/system"):
        return "systemd"
    return "other"


def tool_present(name: str) -> bool:
    return shutil.which(name) is not None


def _run(cmd: list[str], timeout: int = 5) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace", check=False
        )
        return r.returncode, r.stdout, r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return 127, "", "not available"


def detect_sources(osname: str | None = None) -> dict[str, bool]:
    osname = osname or detect_os()
    sources: dict[str, bool] = {}
    if osname == "linux":
        sources["journal"] = tool_present("journalctl")
        sources["coredump"] = tool_present("coredumpctl")
    elif osname == "windows":
        sources["windows_events"] = True  # wevtutil/powershell present on modern windows
        sources["wer"] = True
    elif osname == "macos":
        sources["macos_log"] = tool_present("log")
        sources["diagnostic"] = True
        sources["pmset"] = tool_present("pmset")
    return sources


def detect_elevation(osname: str | None = None) -> dict[str, bool]:
    osname = osname or detect_os()
    elev: dict[str, bool] = {}
    if osname == "linux":
        # attempt reading full journal
        rc, _, _ = _run(
            ["journalctl", "--since", "1 minute ago", "-n", "1", "--no-pager"], timeout=5
        )
        elev["journal_full"] = rc == 0
        # security log access approximated by auth log readability
        elev["security_log"] = (
            os.access("/var/log/auth.log", os.R_OK)
            if os.path.exists("/var/log/auth.log")
            else False
        )
    elif osname == "windows":
        elev["security_log"] = False
    else:
        elev["security_log"] = False
    return elev


def detect_all() -> dict:
    osname = detect_os()
    return {
        "os": osname,
        "os_version": detect_os_version(),
        "init": detect_init(),
        "sources": detect_sources(osname),
        "elevation": detect_elevation(osname),
    }
