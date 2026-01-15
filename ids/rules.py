from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Alert:
    rule_id: str
    severity: str          # "low" | "medium" | "high"
    message: str
    metadata: dict[str, Any]


def generate_ssh_bruteforce_alerts(
    summary: dict,
    per_ip_threshold: int = 5,
    total_threshold: int = 20,
) -> list[Alert]:
    """
    Rule-based detection for SSH failures.

    - If a single IP has >= per_ip_threshold failures (in our current parsed window),
      flag it as a brute-force attempt.
    - If total failures across all IPs >= total_threshold, flag a spray attack.
    """
    alerts: list[Alert] = []

    by_ip = summary.get("by_ip", [])
    total = summary.get("total_failures", 0)

    # Rule 1: per-IP brute force
    for item in by_ip:
        ip = item.get("ip")
        failures = int(item.get("failures", 0))

        if failures >= per_ip_threshold:
            alerts.append(
                Alert(
                    rule_id="SSH_BRUTEFORCE_IP_THRESHOLD",
                    severity="high",
                    message=f"Possible SSH brute-force from {ip} ({failures} failures)",
                    metadata={
                        "ip": ip,
                        "failures": failures,
                        "threshold": per_ip_threshold,
                    },
                )
            )

    # Rule 2: total failures spike (spray attack)
    if total >= total_threshold:
        alerts.append(
            Alert(
                rule_id="SSH_FAILURES_TOTAL_THRESHOLD",
                severity="medium",
                message=f"High SSH failure volume ({total} total failures)",
                metadata={
                    "total_failures": total,
                    "threshold": total_threshold,
                },
            )
        )

    return alerts
    
