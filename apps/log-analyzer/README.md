cat > apps/log-analyzer/README.md << 'EOF'
# Log Analyzer

## The Problem

Raw auth logs are high-volume and hard to read. A brute-force attack against SSH generates dozens of identical lines. A successful login after failures — a potential credential compromise — is easy to miss in the noise. Analysts need a parsed summary, not raw log lines.

## The Solution

This script parses a Linux-style SSH auth log (`/var/log/auth.log` format) and generates a structured report covering three detection areas:

1. **Brute-force candidates** — IPs with 3 or more failed login attempts
2. **Login after failures** — successful authentication from an IP that previously failed
3. **High-risk usernames** — targeted accounts that should never authenticate remotely (root, admin, oracle, etc.)

## How to Run

From the **repo root**:

```bash
python3 apps/log-analyzer/analyze_logs.py
```

## Log Format Supported

Standard Linux sshd log lines: