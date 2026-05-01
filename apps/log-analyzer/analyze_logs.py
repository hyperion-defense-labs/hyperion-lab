#!/usr/bin/env python3
"""
Log Analyzer
------------
Parses a Linux-style SSH auth log (data/sample_auth.log) and produces
a summary report covering:
  - Repeated failed login attempts (brute-force candidates)
  - Successful logins that followed failures from the same IP
  - Unusual / high-risk usernames targeted

Run from repo root:
    python apps/log-analyzer/analyze_logs.py
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_FILE = Path("data/sample_auth.log")

# Usernames that are always present on Linux but should never log in remotely.
HIGH_RISK_USERS = {"root", "admin", "oracle", "test", "guest", "nobody",
                   "daemon", "bin", "sys", "xmrig", "scanner", "nagios"}

# How many failures from one IP before we flag it as a brute-force candidate.
BRUTE_FORCE_THRESHOLD = 3

# Colour helpers
COLOUR = {
    "RED":    "\033[91m",
    "YELLOW": "\033[93m",
    "GREEN":  "\033[92m",
    "CYAN":   "\033[96m",
    "BOLD":   "\033[1m",
    "DIM":    "\033[2m",
    "RESET":  "\033[0m",
}

def c(key: str) -> str:
    return COLOUR[key] if sys.stdout.isatty() else ""


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

# Matches lines like:
#   Nov  1 07:12:03 webserver sshd[2201]: Failed password for (invalid user) <user> from <ip> port <n> ssh2
#   Nov  1 07:13:01 webserver sshd[2205]: Accepted password for <user> from <ip> port <n> ssh2
LINE_RE = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)"
)


def parse_log(path: Path) -> list[dict]:
    """Read the log file and return a list of parsed event dicts."""
    if not path.exists():
        print(f"[ERROR] Log file not found: {path}", file=sys.stderr)
        sys.exit(1)

    events = []
    with path.open() as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            m = LINE_RE.search(line)
            if m:
                events.append({
                    "lineno":    lineno,
                    "timestamp": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                    "status":    m.group("status"),   # "Failed" | "Accepted"
                    "user":      m.group("user"),
                    "ip":        m.group("ip"),
                    "raw":       line,
                })
    return events


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(events: list[dict]) -> dict:
    """
    Derive three detection sets from the parsed events:

    1. brute_force  — IPs with >= BRUTE_FORCE_THRESHOLD failures
    2. login_after_fail — successful logins from an IP that previously failed
    3. risky_users  — high-risk usernames that appeared in any event
    """
    fail_counts:   dict[str, int]       = defaultdict(int)   # ip → failure count
    fail_users:    dict[str, set]       = defaultdict(set)   # ip → set of usernames tried
    success_ips:   dict[str, list]      = defaultdict(list)  # ip → [event, ...]
    risky_targets: dict[str, list]      = defaultdict(list)  # user → [event, ...]

    for ev in events:
        ip   = ev["ip"]
        user = ev["user"]

        if ev["status"] == "Failed":
            fail_counts[ip] += 1
            fail_users[ip].add(user)
            if user in HIGH_RISK_USERS:
                risky_targets[user].append(ev)

        else:  # Accepted
            success_ips[ip].append(ev)

    # Brute-force candidates
    brute_force = {
        ip: {"count": cnt, "users": fail_users[ip]}
        for ip, cnt in fail_counts.items()
        if cnt >= BRUTE_FORCE_THRESHOLD
    }

    # Successful login after failures from the same IP
    login_after_fail = {
        ip: events
        for ip, events in success_ips.items()
        if ip in fail_counts
    }

    return {
        "total_events":    len(events),
        "brute_force":     brute_force,
        "login_after_fail": login_after_fail,
        "risky_users":     dict(risky_targets),
    }


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_banner():
    print(f"\n{c('BOLD')}{'=' * 62}{c('RESET')}")
    print(f"{c('BOLD')}  HYPERION LABS — Log Analyzer{c('RESET')}")
    print(f"{c('BOLD')}{'=' * 62}{c('RESET')}\n")


def print_section(title: str):
    print(f"{c('BOLD')}{c('CYAN')}  ── {title}{c('RESET')}")
    print()


def print_report(results: dict):
    print(f"  Log file : {LOG_FILE}")
    print(f"  Events parsed : {results['total_events']}\n")

    # --- Brute-force candidates ----------------------------------------
    print_section("Brute-Force Candidates (≥ 3 failures per IP)")
    bf = results["brute_force"]
    if bf:
        for ip, data in sorted(bf.items(), key=lambda x: -x[1]["count"]):
            flag = c("RED") + "⚑" + c("RESET") if data["count"] >= 7 else c("YELLOW") + "▲" + c("RESET")
            users_str = ", ".join(sorted(data["users"]))
            print(f"    {flag}  {ip:<20} {data['count']:>3} failures   users: {users_str}")
        print()
    else:
        print(f"    {c('DIM')}None detected.{c('RESET')}\n")

    # --- Login after failures ------------------------------------------
    print_section("Successful Login After Prior Failures (same IP)")
    laf = results["login_after_fail"]
    if laf:
        for ip, successes in laf.items():
            for ev in successes:
                print(f"    {c('YELLOW')}!{c('RESET')}  {ip:<20} user={ev['user']:<15} at {ev['timestamp']}")
        print()
    else:
        print(f"    {c('DIM')}None detected.{c('RESET')}\n")

    # --- High-risk usernames ------------------------------------------
    print_section("High-Risk Usernames Targeted")
    ru = results["risky_users"]
    if ru:
        for user, evs in sorted(ru.items()):
            ips = sorted({e["ip"] for e in evs})
            print(f"    {c('RED')}✖{c('RESET')}  {user:<15}  {len(evs):>2} attempt(s)  from: {', '.join(ips)}")
        print()
    else:
        print(f"    {c('DIM')}None detected.{c('RESET')}\n")

    # --- Summary ------------------------------------------------------
    print(f"{c('BOLD')}{'─' * 62}{c('RESET')}")
    print(f"{c('BOLD')}  Summary{c('RESET')}")
    print(f"{'─' * 62}")
    print(f"  Brute-force candidates   : {c('RED')}{len(results['brute_force'])}{c('RESET')}")
    print(f"  Login-after-fail sources : {c('YELLOW')}{len(results['login_after_fail'])}{c('RESET')}")
    print(f"  High-risk usernames seen : {c('RED')}{len(results['risky_users'])}{c('RESET')}")
    print(f"{c('BOLD')}{'=' * 62}{c('RESET')}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print_banner()
    events  = parse_log(LOG_FILE)
    results = analyze(events)
    print_report(results)


if __name__ == "__main__":
    main()