#!/usr/bin/env python3
"""
Alert Triage Engine
-------------------
Reads alerts from data/sample_alerts.json, classifies each by severity
(LOW / MEDIUM / HIGH), and prints a sorted triage report.

Run from repo root:
    python apps/alert-triage-engine/triage.py
"""

import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ALERTS_FILE = Path("data/sample_alerts.json")

# IPs flagged as malicious in the local threat intel feed.
# In a real environment these would be loaded from a live feed or database.
KNOWN_BAD_IPS = {
    "198.51.100.77",
    "203.0.113.99",
    "198.51.100.22",
    "45.33.32.156",
    "185.220.101.5",
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Colour codes for terminal output (disabled automatically if not a TTY)
COLOUR = {
    "HIGH":   "\033[91m",  # red
    "MEDIUM": "\033[93m",  # yellow
    "LOW":    "\033[92m",  # green
    "RESET":  "\033[0m",
    "BOLD":   "\033[1m",
    "DIM":    "\033[2m",
}

def supports_colour() -> bool:
    return sys.stdout.isatty()

def c(key: str) -> str:
    """Return colour escape if the terminal supports it, else empty string."""
    return COLOUR[key] if supports_colour() else ""


# ---------------------------------------------------------------------------
# Triage logic
# ---------------------------------------------------------------------------

def classify_alert(alert: dict) -> str:
    """
    Apply triage rules and return a severity string.

    Rules (evaluated top-to-bottom; first match wins):
      1. src_ip is in KNOWN_BAD_IPS        → HIGH
      2. failed_login with count >= 10     → HIGH
      3. event_type is port_scan           → MEDIUM
      4. event_type is suspicious_dns      → MEDIUM
      5. everything else                   → LOW
    """
    src_ip     = alert.get("src_ip", "")
    event_type = alert.get("event_type", "")
    count      = alert.get("count", 0)

    if src_ip in KNOWN_BAD_IPS:
        return "HIGH"

    if event_type == "failed_login" and count >= 10:
        return "HIGH"

    if event_type in ("port_scan", "suspicious_dns"):
        return "MEDIUM"

    return "LOW"


def load_alerts(path: Path) -> list[dict]:
    """Load and validate the alert JSON file."""
    if not path.exists():
        print(f"[ERROR] Alert file not found: {path}", file=sys.stderr)
        sys.exit(1)

    with path.open() as f:
        try:
            alerts = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse {path}: {e}", file=sys.stderr)
            sys.exit(1)

    if not isinstance(alerts, list):
        print(f"[ERROR] Expected a JSON array in {path}", file=sys.stderr)
        sys.exit(1)

    return alerts


def triage(alerts: list[dict]) -> list[dict]:
    """Classify each alert and sort by severity (HIGH first)."""
    for alert in alerts:
        alert["severity"] = classify_alert(alert)

    return sorted(alerts, key=lambda a: SEVERITY_ORDER[a["severity"]])


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_banner():
    print(f"\n{c('BOLD')}{'=' * 62}{c('RESET')}")
    print(f"{c('BOLD')}  HYPERION LABS — Alert Triage Engine{c('RESET')}")
    print(f"{c('BOLD')}{'=' * 62}{c('RESET')}\n")


def print_alert(alert: dict):
    sev    = alert["severity"]
    colour = c(sev)
    reset  = c("RESET")
    bold   = c("BOLD")
    dim    = c("DIM")

    src_ip   = alert.get("src_ip") or "n/a"
    username = alert.get("username") or "n/a"

    print(f"  {bold}[{colour}{sev:6}{reset}{bold}]{reset}  {alert['id']}")
    print(f"  {dim}{'─' * 58}{reset}")
    print(f"    Event   : {alert.get('event_type', 'unknown')}")
    print(f"    Source  : {alert.get('source', 'unknown')}")
    print(f"    Src IP  : {src_ip}")
    print(f"    User    : {username}")
    print(f"    Count   : {alert.get('count', 'n/a')}")
    print(f"    Message : {alert.get('message', '')}")
    print(f"    Time    : {alert.get('timestamp', '')}")
    print()


def print_summary(triaged: list[dict]):
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in triaged:
        counts[a["severity"]] += 1

    print(f"{c('BOLD')}{'─' * 62}{c('RESET')}")
    print(f"{c('BOLD')}  Summary{c('RESET')}")
    print(f"{'─' * 62}")
    print(f"  Total alerts : {len(triaged)}")
    print(f"  {c('HIGH')}HIGH   : {counts['HIGH']}{c('RESET')}")
    print(f"  {c('MEDIUM')}MEDIUM : {counts['MEDIUM']}{c('RESET')}")
    print(f"  {c('LOW')}LOW    : {counts['LOW']}{c('RESET')}")
    print(f"{c('BOLD')}{'=' * 62}{c('RESET')}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print_banner()

    raw     = load_alerts(ALERTS_FILE)
    triaged = triage(raw)

    print(f"  Loaded {len(triaged)} alerts from {ALERTS_FILE}\n")
    print(f"{'─' * 62}\n")

    for alert in triaged:
        print_alert(alert)

    print_summary(triaged)


if __name__ == "__main__":
    main()