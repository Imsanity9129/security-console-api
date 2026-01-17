from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import List, Optional


# Example lines we are parsing:
# 2026-01-14T21:57:38.114761-05:00 madmanserver sshd[35183]: Failed password for madman from 10.0.0.25 port 58157 ssh2
# 2026-01-14T21:57:47.988523-05:00 madmanserver sshd[35183]: message repeated 2 times: [ Failed password for madman from 10.0.0.25 port 58157 ssh2]


FAILED_PW_RE = re.compile(
    r"""
    ^(?P<ts>\S+)\s+                # timestamp token (ISO-ish)
    (?P<host>\S+)\s+               # hostname
    sshd\[(?P<pid>\d+)\]:\s+       # sshd[PID]:
    Failed\spassword\sfor\s
    (?P<user>\S+)\sfrom\s
    (?P<ip>\d+\.\d+\.\d+\.\d+)\sport\s
    (?P<port>\d+)\s
    ssh2
    \s*$
    """,
    re.VERBOSE,
)

REPEATED_RE = re.compile(
    r"""
    ^(?P<ts>\S+)\s+
    (?P<host>\S+)\s+
    sshd\[(?P<pid>\d+)\]:\s+
    message\srepeated\s(?P<count>\d+)\stimes:\s+\[\s*
    (?P<inner>.+)
    \s*\]\s*$
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
class SshFailureEvent:
    ts: str                  # keep original timestamp string for now
    host: str
    pid: int
    user: str
    ip: str
    port: int
    count: int
    raw: str = " "	    # 1 for normal lines, >1 for "message repeated"


def parse_line_to_failure_events(line: str) -> List[SshFailureEvent]:
    """
    Return 0 or 1 SshFailureEvent for a single log line.
    If the line is a 'message repeated N times' wrapper around a Failed password line,
    we return one event with count = N (NOT N+1), because the log explicitly says 'repeated N times'.
    We'll handle totals by summing counts across events.
    """
    line = line.strip()

    # Case 1: direct "Failed password ..."
    m = FAILED_PW_RE.match(line)
    if m:
        return [
            SshFailureEvent(
                ts=m.group("ts"),
                host=m.group("host"),
                pid=int(m.group("pid")),
                user=m.group("user"),
                ip=m.group("ip"),
                port=int(m.group("port")),
                count=1,
		raw=line.strip(),
            )
        ]

    # Case 2: "message repeated N times: [ Failed password ... ]"
    r = REPEATED_RE.match(line)
    if r:
        inner = r.group("inner").strip()

        m2 = re.match(r"^Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2\s*$", inner)
        if not m2:
            return []

        return [
            SshFailureEvent(
                ts=r.group("ts"),
                host=r.group("host"),
                pid=int(r.group("pid")),
                user=m2.group(1),
                ip=m2.group(2),
                port=int(m2.group(3)),
                count=int(r.group("count")),
		raw=line.strip(),
            )
        ]

    return []


def read_recent_ssh_failures(
    auth_log_path: str = "/var/log/auth.log",
    tail_lines: int = 500,
) -> List[SshFailureEvent]:
    """
    Reads the last `tail_lines` lines from auth.log (bounded),
    parses SSH 'Failed password' events, and returns structured events.
    """
    # We read the file normally (no shell), but still need root permissions on many systems.
    with open(auth_log_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    recent = lines[-tail_lines:]
    events: List[SshFailureEvent] = []

    for line in recent:
        # Only bother scanning lines containing sshd to reduce work
        if "sshd" not in line:
            continue
        events.extend(parse_line_to_failure_events(line))

    return events

def summarize_failures(events: List[SshFailureEvent], top_n: int = 5) -> dict:
    """
    Turn a list of SshFailureEvent into a JSON-friendly summary.

    Definitions:
    - total_failures: total number of failed password attempts (sums event.count)
    - attempt_sessions: number of distinct SSH login "sessions" we observed, grouped by (ip, port, pid, user)
      This often matches "how many times I tried to SSH in" better than total_failures.
    - by_ip: list of {ip, failures, sessions}, sorted by failures desc
    """
    # Count failures per IP
    failures_by_ip: dict[str, int] = {}

    # Track distinct "sessions" per IP using a set of unique keys
    sessions_by_ip: dict[str, set[tuple[str, int, int, str]]] = {}

    for e in events:
        # failures
        failures_by_ip[e.ip] = failures_by_ip.get(e.ip, 0) + e.count

        # sessions
        key = (e.ip, e.port, e.pid, e.user)
        if e.ip not in sessions_by_ip:
            sessions_by_ip[e.ip] = set()
        sessions_by_ip[e.ip].add(key)

    # Build a combined list for output
    by_ip = []
    for ip, failures in failures_by_ip.items():
        sessions = len(sessions_by_ip.get(ip, set()))
        by_ip.append({"ip": ip, "failures": failures, "sessions": sessions})

    # Sort by failures desc, then sessions desc (nice tie-break)
    by_ip.sort(key=lambda item: (item["failures"], item["sessions"]), reverse=True)

    total_failures = sum(item["failures"] for item in by_ip)
    attempt_sessions = sum(item["sessions"] for item in by_ip)

    return {
        "total_failures": total_failures,
        "attempt_sessions": attempt_sessions,
        "unique_ips": len(by_ip),
        "by_ip": by_ip[:top_n],
    }
