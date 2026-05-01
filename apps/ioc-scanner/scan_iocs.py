
"""
IOC Scanner
-----------
Checks a list of indicators (IPs, domains, file hashes) against the local
threat intelligence feed in data/threat_intel.json and prints a clear
match / no-match report.

Run from repo root:
    python apps/ioc-scanner/scan_iocs.py
"""

import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

THREAT_INTEL_FILE = Path("data/threat_intel.json")

# Indicators to scan. In a production tool these would be read from a file,
# piped from stdin, or pulled from a SIEM alert. Hardcoded here for clarity.
SCAN_TARGETS = {
    "ips": [
        "198.51.100.77",   # should match — C2
        "203.0.113.99",    # should match — brute force
        "10.0.1.15",       # clean — internal host
        "45.33.32.156",    # should match — malware distribution
        "8.8.8.8",         # clean — Google DNS
        "185.220.101.5",   # should match — Tor exit
    ],
    "domains": [
        "malware-c2-example.net",   # should match
        "phish-login-example.com",  # should match
        "google.com",               # clean
        "dga-pattern-abc123.xyz",   # should match
        "github.com",               # clean
    ],
    "hashes": [
        "d41d8cd98f00b204e9800998ecf8427e",   # should match — MD5
        "e3b0c44298fc1c149afbf4c8996fb924",   # should match — SHA256
        "aabbccddeeff00112233445566778899",    # should match — trojan
        "abc123def456000111222333444555ab",    # clean — not in feed
    ],
}

# Colour helpers
COLOUR = {
    "RED":    "\033[91m",
    "GREEN":  "\033[92m",
    "YELLOW": "\033[93m",
    "CYAN":   "\033[96m",
    "BOLD":   "\033[1m",
    "DIM":    "\033[2m",
    "RESET":  "\033[0m",
}

def c(key: str) -> str:
    return COLOUR[key] if sys.stdout.isatty() else ""


# ---------------------------------------------------------------------------
# Threat intel loading
# ---------------------------------------------------------------------------

def load_threat_intel(path: Path) -> dict:
    """Load the threat intel JSON and build lookup sets keyed by indicator value."""
    if not path.exists():
        print(f"[ERROR] Threat intel file not found: {path}", file=sys.stderr)
        sys.exit(1)

    with path.open() as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse {path}: {e}", file=sys.stderr)
            sys.exit(1)

    indicators = data.get("indicators", {})

    # Build value → metadata dicts for O(1) lookups
    index: dict[str, dict[str, dict]] = {"ips": {}, "domains": {}, "hashes": {}}
    for itype in ("ips", "domains", "hashes"):
        for entry in indicators.get(itype, []):
            index[itype][entry["value"].lower()] = entry

    return index


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

ScanResult = dict  # type alias for readability

def scan(targets: dict, intel: dict) -> dict[str, list[ScanResult]]:
    """
    Compare each target indicator against the intel index.

    Returns a dict with keys 'matches' and 'clean', each containing a list
    of result records.
    """
    matches: list[ScanResult] = []
    clean:   list[ScanResult] = []

    for itype, values in targets.items():
        for value in values:
            hit = intel[itype].get(value.lower())
            # Map plural key names to clean display labels
            type_label = {"ips": "ip", "domains": "domain", "hashes": "hash"}
            record = {"type": type_label.get(itype, itype), "value": value}

            if hit:
                record.update({
                    "matched":     True,
                    "threat_type": hit.get("threat_type", "unknown"),
                    "confidence":  hit.get("confidence", "unknown"),
                    "source":      hit.get("source", "unknown"),
                })
                matches.append(record)
            else:
                record["matched"] = False
                clean.append(record)

    return {"matches": matches, "clean": clean}


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

CONFIDENCE_COLOUR = {
    "high":   "RED",
    "medium": "YELLOW",
    "low":    "DIM",
}

def print_banner():
    print(f"\n{c('BOLD')}{'=' * 62}{c('RESET')}")
    print(f"{c('BOLD')}  HYPERION LABS — IOC Scanner{c('RESET')}")
    print(f"{c('BOLD')}{'=' * 62}{c('RESET')}\n")


def print_report(results: dict[str, list[ScanResult]]):
    matches = results["matches"]
    clean   = results["clean"]

    total = len(matches) + len(clean)

    print(f"  Intel feed   : {THREAT_INTEL_FILE}")
    print(f"  Indicators   : {total} scanned  |  "
          f"{c('RED')}{len(matches)} matched{c('RESET')}  |  "
          f"{c('GREEN')}{len(clean)} clean{c('RESET')}\n")

    # --- Matches -------------------------------------------------------
    print(f"{c('BOLD')}{c('RED')}  ── IOC Matches{c('RESET')}\n")
    if matches:
        for r in matches:
            conf_col = CONFIDENCE_COLOUR.get(r["confidence"], "RESET")
            print(f"    {c('RED')}✖  MATCH{c('RESET')}  [{r['type'].upper():<6}]  {r['value']}")
            print(f"           Threat   : {r['threat_type']}")
            print(f"           Confidence: {c(conf_col)}{r['confidence']}{c('RESET')}")
            print(f"           Source   : {r['source']}")
            print()
    else:
        print(f"    {c('DIM')}No matches found.{c('RESET')}\n")

    # --- Clean indicators ----------------------------------------------
    print(f"{c('BOLD')}{c('GREEN')}  ── Clean Indicators{c('RESET')}\n")
    if clean:
        for r in clean:
            print(f"    {c('GREEN')}✔  CLEAN {c('RESET')}  [{r['type'].upper():<6}]  {r['value']}")
        print()
    else:
        print(f"    {c('DIM')}None.{c('RESET')}\n")

    # --- Summary -------------------------------------------------------
    print(f"{c('BOLD')}{'─' * 62}{c('RESET')}")
    print(f"{c('BOLD')}  Summary{c('RESET')}")
    print(f"{'─' * 62}")
    print(f"  Total scanned : {total}")
    print(f"  Matched (IOC) : {c('RED')}{len(matches)}{c('RESET')}")
    print(f"  Clean         : {c('GREEN')}{len(clean)}{c('RESET')}")
    match_rate = len(matches) / total * 100 if total else 0
    print(f"  Hit rate      : {match_rate:.1f}%")
    print(f"{c('BOLD')}{'=' * 62}{c('RESET')}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print_banner()
    intel   = load_threat_intel(THREAT_INTEL_FILE)
    results = scan(SCAN_TARGETS, intel)
    print_report(results)


if __name__ == "__main__":
    main()