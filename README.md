# Hyperion Labs

A portfolio monorepo demonstrating SOC automation and cybersecurity tooling built in Python. The three tools here simulate core pieces of a Security Operations Center (SOC) workflow: alert triage, log analysis, and indicator-of-compromise (IOC) matching.

This is a learning and portfolio project. The tools are functional and use realistic data formats, but they are not production systems.

---

## Tools

| Tool | Purpose |
|---|---|
| **Alert Triage Engine** | Classifies incoming alerts by severity and sorts them for analyst review |
| **Log Analyzer** | Parses SSH auth logs to surface brute-force attempts and suspicious logins |
| **IOC Scanner** | Checks IPs, domains, and file hashes against a local threat intelligence feed |

---

## Quick Start

```bash
# Clone and enter the repo
git clone https://github.com/your-username/hyperion-labs.git
cd hyperion-labs

# No dependencies to install — standard library only
python apps/alert-triage-engine/triage.py
python apps/log-analyzer/analyze_logs.py
python apps/ioc-scanner/scan_iocs.py
```

All scripts are run from the **repo root**. They read sample data from the `data/` directory.

---

## Repository Structure

```
hyperion-labs/
├── README.md
├── .gitignore
├── requirements.txt
├── data/
│   ├── sample_alerts.json    # Alert records for triage engine
│   ├── sample_auth.log       # Linux SSH auth log for log analyzer
│   └── threat_intel.json     # IOC feed for scanner
├── apps/
│   ├── alert-triage-engine/
│   │   ├── README.md
│   │   └── triage.py
│   ├── log-analyzer/
│   │   ├── README.md
│   │   └── analyze_logs.py
│   └── ioc-scanner/
│       ├── README.md
│       └── scan_iocs.py
└── docs/
    └── soc-workflow-overview.md
```

---

## Why This Matters in a SOC

SOC analysts deal with high alert volumes, noisy logs, and constantly evolving threat feeds. Manual review doesn't scale. Even simple automation like this reduces time-to-triage and helps analysts focus on what actually needs human attention.

- **Alert triage** ensures the highest-severity events get reviewed first.
- **Log analysis** turns raw auth logs into actionable detection signals without manual grep chains.
- **IOC scanning** operationalizes threat intelligence by checking observed indicators against known bad.

These tools reflect the same workflow used by enterprise SIEM platforms — just without the licensing cost.

---

## Requirements

- Python 3.9+
- No external dependencies (standard library only)

---

## Author

Built as a cybersecurity engineering portfolio project. See `docs/soc-workflow-overview.md` for how the tools connect end-to-end.