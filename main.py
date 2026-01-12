from __future__ import annotations

from datetime import datetime, timezone
import os
import platform
import shutil
import subprocess

from fastapi import FastAPI


app = FastAPI(
    title="Security Console API",
    version="0.1.0",
)


def run_cmd(argv: list[str], timeout_s: int = 2) -> dict:
    """
    Run a system command safely (no shell).
    Returns a small structured result.
    """
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        return {
            "argv": argv,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except FileNotFoundError:
        return {"argv": argv, "error": "not_found"}
    except subprocess.TimeoutExpired:
        return {"argv": argv, "error": "timeout"}


@app.get("/health")
def health():
    return {
        "status": "ok",
        "time_utc": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/sysinfo")
def sysinfo():
    # Host / OS identity
    hostname = platform.node()
    os_info = {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
    }

    # Uptime (Linux)
    uptime_seconds = None
    try:
        with open("/proc/uptime", "r", encoding="utf-8") as f:
            uptime_seconds = float(f.read().split()[0])
    except Exception:
        uptime_seconds = None

    # Load average (Linux/Unix)
    load_avg = None
    try:
        one, five, fifteen = os.getloadavg()
        load_avg = {"1m": one, "5m": five, "15m": fifteen}
    except Exception:
        load_avg = None

    # Memory (Linux)
    mem = None
    try:
        meminfo = {}
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                key, value = line.split(":", 1)
                meminfo[key.strip()] = value.strip()
        mem = {
            "MemTotal": meminfo.get("MemTotal"),
            "MemAvailable": meminfo.get("MemAvailable"),
            "SwapTotal": meminfo.get("SwapTotal"),
            "SwapFree": meminfo.get("SwapFree"),
        }
    except Exception:
        mem = None

    # Disk usage for root filesystem
    du = shutil.disk_usage("/")
    disk = {
        "path": "/",
        "total_bytes": du.total,
        "used_bytes": du.used,
        "free_bytes": du.free,
    }

    # Optional: a couple simple commands (still safe)
    whoami = run_cmd(["whoami"])
    uname = run_cmd(["uname", "-a"])

    return {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "hostname": hostname,
        "os": os_info,
        "uptime_seconds": uptime_seconds,
        "load_avg": load_avg,
        "memory": mem,
        "disk": disk,
        "whoami": whoami,
        "uname": uname,
    }
