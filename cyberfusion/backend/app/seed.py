"""First-run setup: controls catalogue, admin user, and (optionally) clearly-labelled demo data."""
import os
import random
import secrets
from datetime import timedelta

from sqlalchemy.orm import Session

from . import detection
from .models import (Alert, Asset, CloudFinding, Control, Event, Incident, Indicator, SoarAction, User,
                     Vulnerability, now)
from .security import audit, hash_password

CONTROLS = [
    # NIST Cybersecurity Framework
    ("NIST CSF", "ID.AM-1", "Physical devices and systems are inventoried", "config_management"),
    ("NIST CSF", "ID.RA-1", "Asset vulnerabilities are identified and documented", "vulnerability_management"),
    ("NIST CSF", "PR.AC-1", "Identities and credentials are managed for authorized users", "access_control"),
    ("NIST CSF", "PR.DS-1", "Data-at-rest is protected", "encryption"),
    ("NIST CSF", "PR.DS-2", "Data-in-transit is protected", "encryption"),
    ("NIST CSF", "PR.PT-1", "Audit/log records are determined, documented and reviewed", "logging_monitoring"),
    ("NIST CSF", "PR.IP-1", "A baseline configuration is maintained", "config_management"),
    ("NIST CSF", "DE.CM-1", "The network is monitored to detect potential cybersecurity events", "network_security"),
    ("NIST CSF", "DE.CM-4", "Malicious code is detected", "endpoint_protection"),
    ("NIST CSF", "RS.RP-1", "Response plan is executed during or after an event", "incident_response"),
    # ISO 27001:2022 Annex A
    ("ISO 27001", "A.5.15", "Access control", "access_control"),
    ("ISO 27001", "A.8.7", "Protection against malware", "endpoint_protection"),
    ("ISO 27001", "A.8.8", "Management of technical vulnerabilities", "vulnerability_management"),
    ("ISO 27001", "A.8.9", "Configuration management", "config_management"),
    ("ISO 27001", "A.8.15", "Logging", "logging_monitoring"),
    ("ISO 27001", "A.8.16", "Monitoring activities", "network_security"),
    ("ISO 27001", "A.8.24", "Use of cryptography", "encryption"),
    ("ISO 27001", "A.5.26", "Response to information security incidents", "incident_response"),
    # CIS Controls v8
    ("CIS Controls", "CIS 1", "Inventory and control of enterprise assets", "config_management"),
    ("CIS Controls", "CIS 3", "Data protection", "encryption"),
    ("CIS Controls", "CIS 4", "Secure configuration of enterprise assets and software", "config_management"),
    ("CIS Controls", "CIS 5/6", "Account and access control management", "access_control"),
    ("CIS Controls", "CIS 7", "Continuous vulnerability management", "vulnerability_management"),
    ("CIS Controls", "CIS 8", "Audit log management", "logging_monitoring"),
    ("CIS Controls", "CIS 10", "Malware defenses", "endpoint_protection"),
    ("CIS Controls", "CIS 13", "Network monitoring and defense", "network_security"),
    ("CIS Controls", "CIS 17", "Incident response management", "incident_response"),
]


def seed(db: Session):
    if not db.query(Control).first():
        db.add_all(Control(framework=f, control_id=c, title=t, category=cat) for f, c, t, cat in CONTROLS)
        db.commit()

    if not db.query(User).first():
        pw = os.getenv("ADMIN_PASSWORD")
        generated = pw is None
        pw = pw or secrets.token_urlsafe(16) + "Aa1"
        db.add(User(username="admin", password_hash=hash_password(pw), role="admin"))
        db.commit()
        audit(db, "system", "bootstrap_admin_created", "admin")
        if generated:
            print("\n" + "=" * 64 + f"\n  CyberFusion first run. Admin login:  admin / {pw}\n"
                  "  Change this, or set ADMIN_PASSWORD before first start.\n" + "=" * 64 + "\n")

    if os.getenv("DEMO_DATA", "true").lower() == "true" and not db.query(Asset).first():
        seed_demo(db)


def seed_demo(db: Session):
    random.seed(7)
    demo_pw = os.getenv("DEMO_PASSWORD", "CyberFusion-Demo-2026")
    for name, role in [("analyst", "analyst"), ("vulnmgr", "vuln_analyst"), ("auditor", "auditor"), ("viewer", "readonly"),
                       ("admin2", "admin")]:
        db.add(User(username=name, password_hash=hash_password(demo_pw), role=role))
    print(f"  DEMO_DATA on: demo users analyst/vulnmgr/auditor/viewer/admin2 share password '{demo_pw}'. "
          "Set DEMO_DATA=false in production.")

    hosts = [("WS-FIN-014", "Windows 11 23H2", "10.0.4.21", "high"), ("WS-HR-007", "Windows 11 22H2", "10.0.4.37", "medium"),
             ("SRV-DC-01", "Windows Server 2022", "10.0.1.10", "critical"), ("SRV-FILE-02", "Windows Server 2019", "10.0.1.22", "high"),
             ("WS-DEV-031", "Windows 10 22H2", "10.0.5.14", "medium"), ("LT-EXEC-003", "Windows 11 23H2", "10.0.6.8", "critical")]
    assets = []
    for i, (h, o, ip, crit) in enumerate(hosts):
        a = Asset(hostname=h, os=o, ip=ip, agent_version="0.1.0", criticality=crit,
                  last_seen=now() - (timedelta(hours=9) if i == 4 else timedelta(seconds=random.randint(5, 200))),
                  telemetry={"defender_enabled": i != 1, "firewall_enabled": True, "patch_status": "pending" if i in (1, 4) else "current",
                             "uptime_hours": random.randint(10, 400)})
        db.add(a)
        assets.append(a)
    db.commit()

    vulns = [(0, "CVE-2024-38063", "Windows TCP/IP remote code execution", "Windows TCPIP", 9.8, 0.62, "Install the August 2024 cumulative update."),
             (2, "CVE-2023-23397", "Outlook elevation of privilege", "Microsoft Outlook", 9.8, 0.94, "Apply Outlook security update; block outbound SMB."),
             (3, "CVE-2023-4863", "libwebp heap buffer overflow", "Chrome 115", 8.8, 0.51, "Update Chrome to a fixed release."),
             (1, "CVE-2024-21412", "SmartScreen bypass", "Windows SmartScreen", 8.1, 0.33, "Install latest cumulative update."),
             (4, "CVE-2022-41040", "Exchange SSRF (ProxyNotShell)", "Exchange Server", 8.8, 0.88, "Apply Exchange SU and URL rewrite mitigation."),
             (5, "CVE-2024-30051", "DWM Core Library elevation of privilege", "Windows DWM", 7.8, 0.12, "Install May 2024 update."),
             (0, "CVE-2023-36884", "Office/Windows HTML RCE", "Microsoft Office", 7.5, 0.27, "Apply Office update."),
             (3, "CVE-2021-3156", "sudo Baron Samedit", "WSL sudo", 7.8, 0.40, "Update sudo in WSL."),
             (5, "CVE-2023-29336", "Win32k elevation of privilege", "Windows Win32k", 5.5, 0.05, "Install May 2023 update.")]
    for ai, cve, title, sw, cvss, epss, rem in vulns:
        sev = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium"
        db.add(Vulnerability(asset_id=assets[ai].id, cve=cve, title=title, software=sw, cvss=cvss, epss=epss,
                             severity=sev, remediation=rem, source="demo",
                             status=random.choice(["open", "open", "open", "in_progress"])))
    db.add(Vulnerability(asset_id=assets[2].id, cve="CVE-2020-1472", title="Zerologon", software="Netlogon", cvss=10.0, epss=0.97,
                         severity="critical", remediation="Enforce secure RPC.", status="verified", source="demo"))

    for ip, mal, camp, conf in [("185.220.101.45", "Cobalt Strike beacon", "FIN7", 90), ("45.9.148.108", "QakBot C2", "TA577", 85)]:
        db.add(Indicator(type="ip", value=ip, reputation="malicious", confidence=conf, malware=mal, campaign=camp,
                         first_seen=now() - timedelta(days=40), last_seen=now() - timedelta(days=1)))
    db.add(Indicator(type="domain", value="update-secure-login.example", reputation="suspicious", confidence=60,
                     campaign="Credential phishing"))
    db.add(Indicator(type="hash", value="44d88612fea8a8f36de82e1278abb02f", reputation="malicious", confidence=99,
                     malware="EICAR test file"))
    db.commit()

    # Replay events through the real detection engine so demo alerts come from the actual rules.
    base = now() - timedelta(days=6)
    for d in range(7):
        for _ in range(random.randint(6, 14)):
            h = random.choice(assets)
            ev = Event(source="windows-eventlog", event_type="auth_success", host=h.hostname,
                       user=random.choice(["jsmith", "mdlamini", "akhan", "svc-backup"]), src_ip=h.ip, outcome="success",
                       message="An account was successfully logged on (4624)",
                       timestamp=base + timedelta(days=d, minutes=random.randint(0, 1400)))
            db.add(ev)
    db.commit()

    t = now() - timedelta(hours=3)
    for k in range(6):
        ev = Event(source="windows-eventlog", event_type="auth_failure", host="SRV-DC-01", user="administrator",
                   src_ip="185.220.101.45", outcome="failure", message="An account failed to log on (4625)",
                   timestamp=t + timedelta(minutes=k))
        db.add(ev); db.commit(); detection.evaluate(db, ev)
    ev = Event(source="windows-eventlog", event_type="auth_success", host="SRV-DC-01", user="administrator",
               src_ip="185.220.101.45", outcome="success", message="An account was successfully logged on (4624)",
               timestamp=t + timedelta(minutes=8))
    db.add(ev); db.commit(); detection.evaluate(db, ev)
    ev = Event(source="windows-eventlog", event_type="defender_disabled", host="WS-HR-007", user="mdlamini",
               message="Real-time protection disabled (5001)", timestamp=now() - timedelta(hours=1))
    db.add(ev); db.commit(); detection.evaluate(db, ev)
    for a in assets:
        detection.evaluate_posture(db, a.hostname, a.telemetry)

    inc = Incident(title="Suspected compromise of domain controller", severity="critical",
                   detection_source="R2-FAIL-THEN-SUCCESS", affected_assets=["SRV-DC-01"], assigned_to="analyst",
                   status="investigating", containment_status="in_progress",
                   timeline=[{"time": (now() - timedelta(hours=2)).isoformat(), "by": "analyst", "entry": "Incident opened from alert"},
                             {"time": (now() - timedelta(hours=1)).isoformat(), "by": "analyst", "entry": "Source IP confirmed malicious in threat intel"}],
                   evidence=[{"type": "ip", "ref": "185.220.101.45", "summary": "Cobalt Strike infrastructure"}])
    db.add(inc)
    db.commit()
    crit = db.query(Alert).filter(Alert.rule == "R2-FAIL-THEN-SUCCESS").first()
    if crit:
        crit.incident_id, crit.status = inc.id, "investigating"
    db.add(SoarAction(action="isolate_endpoint", asset_id=assets[2].id, incident_id=inc.id, requested_by="analyst",
                      reason="Confirmed login from known C2 address after brute force"))

    for prov, res, cat, title, sev in [
        ("azure", "stfinancedata01", "network_security", "Storage account allows public blob access", "high"),
        ("aws", "s3://acme-backups", "encryption", "S3 bucket without default encryption", "medium"),
        ("aws", "iam:role/ci-deploy", "access_control", "IAM role with wildcard (*) permissions", "critical"),
        ("gcp", "project/acme-prod", "logging_monitoring", "Cloud Audit Logs disabled for data access", "medium"),
        ("azure", "vm-web-02", "config_management", "VM without endpoint protection extension", "low")]:
        db.add(CloudFinding(provider=prov, resource=res, category=cat, title=title, severity=sev))
    db.commit()
