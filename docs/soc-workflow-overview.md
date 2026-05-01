# SOC Workflow Overview

This document explains how the three Hyperion Labs tools map to a real SOC detection and response workflow.

---

## The Detection Pipeline

```
Raw Events & Logs
       │
       ▼
┌─────────────────┐
│   Log Analyzer  │  ← parse auth logs → detect brute force, suspicious logins
└────────┬────────┘
         │ findings (IPs, usernames, event patterns)
         ▼
┌──────────────────────┐
│  Alert Triage Engine │  ← classify alerts by severity → sort for analyst queue
└──────────┬───────────┘
           │ HIGH / MEDIUM alerts
           ▼
┌────────────────┐
│   IOC Scanner  │  ← check IPs, domains, hashes against threat intel feed
└────────┬───────┘
         │ confirmed matches
         ▼
  Analyst Review
```

---

## Stage 1 — Log Analysis

The Log Analyzer ingests raw system logs and converts them into structured detection signals. For SSH auth logs, it identifies brute-force candidates, successful logins that followed failures, and targeted high-risk usernames. This stage answers: *"What happened in the logs, and what looks suspicious?"*

In a production environment, this stage is handled by a log aggregator (Splunk, Elastic, Graylog) with detection rules. The Log Analyzer replicates that logic in a standalone script.

---

## Stage 2 — Alert Triage

The Alert Triage Engine consumes alert records — either from a SIEM or from structured output from the Log Analyzer — and classifies them as LOW, MEDIUM, or HIGH. Alerts are sorted so analysts work the most critical items first.

This stage answers: *"Of everything that triggered, what needs immediate attention?"*

Without triage, a 5-failure brute-force attempt from an internal IP competes for attention with a 14-failure attack from a known-bad external IP. Triage fixes that ordering.

---

## Stage 3 — IOC Scanning

Once a suspicious IP, domain, or file hash is identified (from triage or log analysis), it can be checked against the threat intelligence feed. The IOC Scanner answers: *"Is this indicator already known to be malicious?"*

A match gives the analyst instant context — what threat type, how confident the intel source is, and where the indicator was reported. A non-match doesn't clear the indicator; it just means it isn't in the local feed and may warrant further investigation (VirusTotal, Shodan, passive DNS, etc.).

---

## How a Real SOC Analyst Uses These Signals

1. **Log Analyzer** surfaces a source IP (`198.51.100.22`) with 7 SSH failures targeting `root` and `xmrig`.
2. **Alert Triage Engine** receives the corresponding alert, recognizes the IP is in the known-bad list, and marks it HIGH.
3. **IOC Scanner** confirms the IP is categorized as a "Scanner" with medium confidence in the threat intel feed.
4. Analyst reviews the HIGH-priority alert, corroborates with the IOC match, and initiates a block on the source IP.

Each tool handles one stage. Together, they reduce the time from raw event to analyst decision.

---

## What's Missing (Intentionally)

These tools simulate the workflow with sample data. A production SOC also relies on:

- **SOAR platforms** for automated response playbooks
- **SIEM correlation** for multi-source alert fusion
- **Live threat feeds** (MISP, OpenCTI, commercial providers) updated continuously
- **Case management** (TheHive, Jira, ServiceNow) for tracking investigations
- **Endpoint telemetry** (EDR) for process and file-level visibility

The goal here is to demonstrate understanding of the workflow and the ability to build functional tooling around it — not to replicate a full enterprise platform.