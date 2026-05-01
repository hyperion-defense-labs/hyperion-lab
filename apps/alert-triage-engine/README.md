cat > apps/alert-triage-engine/README.md << 'EOF'
# Alert Triage Engine

## The Problem

A SOC receives dozens to hundreds of alerts per shift. Without prioritization, analysts work the queue in arrival order — meaning a low-noise policy violation gets reviewed before a live brute-force attack. Triage automation fixes that.

## The Solution

This script reads a JSON alert feed, applies a deterministic rule set to classify each alert as `LOW`, `MEDIUM`, or `HIGH`, and prints them sorted by severity so the most urgent items surface first.

## Triage Rules

| Condition | Severity |
|---|---|
| Source IP is in the known-bad IP list | HIGH |
| `failed_login` event with `count >= 10` | HIGH |
| `port_scan` event | MEDIUM |
| `suspicious_dns` event | MEDIUM |
| Everything else | LOW |

Rules are evaluated top-to-bottom. First match wins.

## How to Run

From the **repo root**:

```bash
python3 apps/alert-triage-engine/triage.py
```

## Input Format

`data/sample_alerts.json` — a JSON array of alert objects:

```json
{
  "id": "ALT-001",
  "source": "auth-monitor",
  "event_type": "failed_login",
  "src_ip": "192.168.1.45",
  "username": "admin",
  "message": "Multiple failed login attempts detected",
  "count": 14,
  "timestamp": "2024-11-01T08:23:11Z"
}
```

## Future Improvements

- Load the known-bad IP list from `data/threat_intel.json` instead of hardcoding it
- Add a `--output json` flag for piping results to downstream tooling
- Support alert suppression rules to reduce repeated LOW-severity noise
- Add a scoring model to weight multiple signals per alert
EOF