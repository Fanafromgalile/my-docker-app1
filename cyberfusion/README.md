# CyberFusion

A unified cybersecurity platform MVP: one dashboard over endpoints, vulnerabilities, SIEM events, incidents,
threat intelligence, cloud findings and compliance.

```
Endpoint Agent → HTTPS API → FastAPI backend → Database → React dashboard
```

| Part | Tech | Folder |
|---|---|---|
| Dashboard | React + TypeScript (Vite) | `frontend/` |
| API | FastAPI + SQLAlchemy (SQLite for dev, PostgreSQL in Docker) | `backend/` |
| Endpoint agent | Windows PowerShell | `agent/` |

## Run it

### Docker (PostgreSQL, recommended)
```bash
cp .env.example .env        # set POSTGRES_PASSWORD and SECRET_KEY (see comments in the file)
docker compose up --build
```
Open http://localhost:8080. Put a TLS-terminating proxy (Caddy, nginx, a cloud load balancer) in front for anything
beyond local testing. Agents refuse non-HTTPS servers.

### Local development
```bash
# backend (SQLite file created automatically)
cd backend && python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload            # http://localhost:8000/docs

# frontend (proxies /api to :8000)
cd frontend && npm install && npm run dev   # http://localhost:5173
```

### First login
- Username `admin`. Password is `ADMIN_PASSWORD` if set, otherwise a random one **printed in the backend log on first start**.
- `DEMO_DATA=true` loads demo endpoints, vulnerabilities, events (run through the real detection rules), an incident,
  a pending approval, and demo users `analyst`, `vulnmgr`, `auditor`, `viewer`, `admin2`
  (shared password = `DEMO_PASSWORD`). **Turn this off in production.**

### Enroll a real Windows endpoint
1. Dashboard → Assets → **Enroll endpoint** → copy the single-use token.
2. On the endpoint, in an elevated PowerShell:
   ```powershell
   .\CyberFusionAgent.ps1 -Enroll -Server "https://your-server" -EnrollmentToken "enr_..."
   .\CyberFusionAgent.ps1 -Install      # scheduled task, runs as SYSTEM at boot
   ```

## What's implemented

- **Auth & RBAC** – PBKDF2 password hashing, 30-min JWTs, lockout after 5 failures, login rate limiting, five roles
  (admin, analyst, vuln_analyst, auditor, readonly) enforced server-side and mirrored in the UI.
- **Agent identity** – single-use enrollment tokens; per-agent tokens stored only as SHA-256 hashes; every agent request
  re-authenticated; revocation; DPAPI-encrypted token on the endpoint. The agent is outbound-only with no command channel.
- **Assets / Vulnerabilities** – CVE, CVSS, EPSS, severity, business-risk score (weighted by asset criticality),
  open → in progress → remediated → verified workflow, scanner import endpoint (`/api/integrations/scanner/import`).
- **SIEM** – event ingestion and 6 correlation rules (brute force, fail-then-success, defense evasion, threat-intel match,
  Defender/firewall posture).
- **Incident response** – cases with timeline, evidence, notes, containment/remediation status; alerts convert to incidents.
- **SOAR approvals** – isolate / release / revoke require approval by a different admin (four-eyes).
- **Threat intelligence** – indicator store, lookup/enrichment with local sightings, automatic alerting on malicious IPs.
- **Cloud security** – Azure/AWS/GCP findings (manual/API entry).
- **Compliance** – findings mapped to controls in NIST CSF, ISO 27001 and CIS Controls with remediation guidance.
- **Audit trail** – append-only, hash-chained; "Verify integrity" detects edits or deletions.

## Honest limitations (MVP)

- **Not yet runtime-tested end to end.** This code was written in an environment with no access to PyPI/npm, so it was
  syntax-checked but not executed. Expect to fix small issues on first run, and run `npm run build` (it type-checks).
- **SOAR "isolate" records state in CyberFusion only.** Actually cutting a host off the network needs an EDR/firewall
  integration; the agent deliberately cannot run commands.
- **No MFA, refresh-token rotation or SSO yet**, and the rate limiter is per-process in memory (use Redis or the proxy
  for multi-worker deployments). Agents use bearer tokens, not mTLS/device certificates yet.
- **Cloud and scanner data are not pulled live**; Rapid7/Qualys/Tenable/Sentinel/Splunk connectors are the next step
  (the scanner import endpoint is the normalisation layer they would feed).
- Compliance scores reflect only what CyberFusion can observe; they are not an audit.
- Set `SECRET_KEY`; otherwise a random key is generated per start and all sessions are invalidated on restart.

## Suggested roadmap
PostgreSQL migrations (Alembic) → MFA (TOTP) + refresh rotation → mTLS agent identity → real Windows telemetry
(installed software, services, Event Log subscriptions) → scanner and SIEM connectors → cloud scanners → EDR-backed isolation.
