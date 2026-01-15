from __future__ import annotations

import os
import platform
import shutil
import subprocess

from fastapi import Header, HTTPException, Depends
from datetime import datetime, timezone
from ids.ssh_authlog import read_recent_ssh_failures, summarize_failures
from ids.rules import generate_ssh_bruteforce_alerts

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

def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    expected = os.environ.get("API_KEY")

    if not expected:
        # Server misconfiguration (no API key set)
        raise HTTPException(
            status_code=500,
            detail="API key not configured on server",
        )

    if x_api_key != expected:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
        )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "time_utc": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/sysinfo", dependencies=[Depends(require_api_key)])
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
@app.get("/sessions", dependencies=[Depends(require_api_key)])
def sessions():
    return {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "active_sessions": {
            "who": run_cmd(["who"]),
            "w": run_cmd(["w"]),
        },
    }
    
@app.get("/ufw", dependencies=[Depends(require_api_key)])
def ufw_status():
    return {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "ufw": run_cmd(["sudo", "-n", "/usr/sbin/ufw", "status", "verbose"]),
    }

@app.get("/ssh-failures", dependencies=[Depends(require_api_key)])
def ssh_failures():
    return {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "recent_failures": run_cmd(
            ["bash", "-c", "tail -n 200 /var/log/auth.log | grep 'Failed password' | tail -n 50"]
        ),
    }
@app.get("/ids/ssh/summary", dependencies=[Depends(require_api_key)])
def ids_ssh_summary():
    events = read_recent_ssh_failures()
    return summarize_failures(events)


@app.get("/ids/alerts", dependencies=[Depends(require_api_key)])
def ids_alerts():
    events = read_recent_ssh_failures()
    summary = summarize_failures(events)
    alerts = generate_ssh_bruteforce_alerts(summary)

    # dataclass -> dict so FastAPI can return JSON cleanly
    return [a.__dict__ for a in alerts]
