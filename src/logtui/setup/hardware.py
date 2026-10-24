"""Hardware capability detection."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess


def _run(cmd: list[str], timeout: int = 5) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace", check=False
        )
        return r.returncode, r.stdout, r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return 127, "", "not available"


def detect_wifi() -> str | None:
    osname = platform.system().lower()
    if osname == "linux":
        # check /sys/class/net/*/wireless
        net_dir = "/sys/class/net"
        if os.path.isdir(net_dir):
            for iface in os.listdir(net_dir):
                if os.path.exists(os.path.join(net_dir, iface, "wireless")):
                    # try to identify driver
                    dev = os.path.join(net_dir, iface, "device", "driver")
                    try:
                        link = os.readlink(dev)
                        drv = os.path.basename(link)
                        if drv:
                            return drv
                    except OSError:
                        pass
                    return "unknown"
        # iw tool
        if shutil.which("iw"):
            rc, out, _ = _run(["iw", "dev"])
            if rc == 0 and out.strip():
                return "iw"
        return None
    if osname == "windows":
        rc, out, _ = _run(["netsh", "wlan", "show", "interfaces"])
        if rc == 0 and "Name" in out:
            return "wlan"
        return None
    if osname == "darwin":
        # airport / wdutil
        if shutil.which("wdutil"):
            return "wifi"
        return None
    return None


def detect_bluetooth() -> bool:
    osname = platform.system().lower()
    if osname == "linux":
        if os.path.exists("/sys/class/bluetooth"):
            try:
                return bool(os.listdir("/sys/class/bluetooth"))
            except OSError:
                return False
        return shutil.which("bluetoothctl") is not None
    if osname == "windows":
        # assume present; refine via powershell if needed
        return True
    if osname == "darwin":
        return shutil.which("system_profiler") is not None
    return False


def detect_gpu() -> str | None:
    osname = platform.system().lower()
    if osname == "linux":
        rc, out, _ = _run(["lspci"])
        if rc == 0:
            low = out.lower()
            if "nvidia" in low:
                return "nvidia"
            if "amd" in low or "radeon" in low:
                return "amd"
            if "intel" in low:
                return "intel"
        return None
    if osname == "windows":
        rc, out, _ = _run(["wmic", "path", "win32_VideoController", "get", "name"])
        if rc == 0:
            low = out.lower()
            if "nvidia" in low:
                return "nvidia"
            if "amd" in low or "radeon" in low:
                return "amd"
            if "intel" in low:
                return "intel"
        return None
    if osname == "darwin":
        rc, out, _ = _run(["system_profiler", "SPDisplaysDataType"])
        if rc == 0:
            low = out.lower()
            if "nvidia" in low:
                return "nvidia"
            if "amd" in low or "radeon" in low:
                return "amd"
            if "intel" in low:
                return "intel"
        return "apple" if True else None
    return None


def detect_battery() -> bool:
    osname = platform.system().lower()
    if osname == "linux":
        p = "/sys/class/power_supply"
        if os.path.isdir(p):
            try:
                for e in os.listdir(p):
                    if e.startswith("BAT"):
                        return True
            except OSError:
                pass
        return False
    if osname == "windows":
        rc, out, _ = _run(["wmic", "path", "Win32_Battery", "get", "Status"])
        return rc == 0 and "Status" in out and len(out.splitlines()) > 1
    if osname == "darwin":
        rc, out, _ = _run(["pmset", "-g", "batt"])
        return rc == 0 and "InternalBattery" in out
    return False


def detect_hardware() -> dict:
    return {
        "wifi": detect_wifi(),
        "bluetooth": detect_bluetooth(),
        "gpu": detect_gpu(),
        "battery": detect_battery(),
    }
