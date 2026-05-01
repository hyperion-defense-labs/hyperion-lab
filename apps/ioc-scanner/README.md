cat > apps/ioc-scanner/README.md << 'EOF'
# IOC Scanner

## The Problem

Threat intelligence feeds publish lists of known-bad IPs, domains, and file hashes. Without tooling, operationalizing that intelligence means manually grepping logs or running lookups one indicator at a time. This doesn't scale when you have dozens of indicators to check.

## The Solution

This script checks a list of indicators against a local threat intel feed (`data/threat_intel.json`) and prints a clear match/no-match report. It supports three indicator types:

- **IP addresses** — matched against known C2 servers, scanners, and blocklisted hosts
- **Domains** — matched against C2 domains, phishing sites, and DGA-pattern domains
- **File hashes** — matched against known malware, ransomware, and trojans (MD5 and SHA-256)

## How to Run

From the **repo root**:

```bash
python3 apps/ioc-scanner/scan_iocs.py
```

## Threat Intel Format

`data/threat_intel.json` structure:

```json
{
  "indicators": {
    "ips":     [{ "value": "1.2.3.4", "threat_type": "C2 Server", "confidence": "high", "source": "abuse-ch" }],
    "domains": [{ "value": "evil.net", "threat_type": "Phishing",  "confidence": "high", "source": "openphish" }],
    "hashes":  [{ "value": "abc123...", "threat_type": "Ransomware", "algorithm": "md5", "confidence": "high", "source": "malwarebazaar" }]
  }
}
```

## Future Improvements

- Accept indicators from stdin or a file (`--input iocs.txt`) instead of the hardcoded list
- Support STIX/TAXII feed ingestion for real threat intel sources
- Add VirusTotal API enrichment for unmatched indicators
- Cache results locally to avoid redundant lookups on the same indicator
- Return exit code 1 when matches are found (useful in CI/CD pipeline scanning)
EOF