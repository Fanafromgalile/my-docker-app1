"""SIEM detection: runs correlation rules as each event is ingested."""
from datetime import timedelta
from sqlalchemy.orm import Session
from .models import Alert, Event, Indicator, now

FAIL_THRESHOLD = 5
WINDOW = timedelta(minutes=10)


def _recent_alert(db: Session, rule: str, host: str, key: str) -> bool:
    cutoff = now() - WINDOW
    q = db.query(Alert).filter(Alert.rule == rule, Alert.created_at >= cutoff, Alert.description.contains(key))
    return db.query(q.exists()).scalar()


def _raise(db: Session, title, severity, rule, host, description, source="siem") -> Alert:
    alert = Alert(title=title, severity=severity, rule=rule, host=host, description=description, source=source)
    db.add(alert)
    db.commit()
    return alert


def evaluate(db: Session, ev: Event) -> list[Alert]:
    alerts: list[Alert] = []
    cutoff = ev.timestamp - WINDOW

    # R1 - repeated failed logins (brute force)
    if ev.event_type == "auth_failure" and ev.user:
        n = db.query(Event).filter(Event.event_type == "auth_failure", Event.user == ev.user,
                                   Event.timestamp >= cutoff).count()
        key = f"user={ev.user}"
        if n >= FAIL_THRESHOLD and not _recent_alert(db, "R1-BRUTE-FORCE", ev.host, key):
            alerts.append(_raise(db, f"Brute-force attempt against {ev.user}", "high", "R1-BRUTE-FORCE", ev.host,
                                 f"{n} failed logins in 10 minutes ({key}, src={ev.src_ip})"))

    # R2 - failed logins followed by success (possible compromise)
    if ev.event_type == "auth_success" and ev.user:
        n = db.query(Event).filter(Event.event_type == "auth_failure", Event.user == ev.user,
                                   Event.timestamp >= cutoff, Event.timestamp <= ev.timestamp).count()
        key = f"user={ev.user}"
        if n >= 3 and not _recent_alert(db, "R2-FAIL-THEN-SUCCESS", ev.host, key):
            alerts.append(_raise(db, f"Successful login after {n} failures for {ev.user}", "critical",
                                 "R2-FAIL-THEN-SUCCESS", ev.host,
                                 f"Possible account compromise ({key}, src={ev.src_ip})"))

    # R3 - security tooling disabled
    if ev.event_type in ("defender_disabled", "firewall_disabled", "audit_log_cleared"):
        key = f"type={ev.event_type}"
        if not _recent_alert(db, "R3-DEFENSE-EVASION", ev.host, key):
            alerts.append(_raise(db, f"Defense evasion: {ev.event_type.replace('_', ' ')} on {ev.host}", "high",
                                 "R3-DEFENSE-EVASION", ev.host, f"{key} observed on {ev.host}"))

    # R4 - traffic from a known-malicious indicator
    if ev.src_ip:
        ind = db.query(Indicator).filter(Indicator.value == ev.src_ip, Indicator.reputation == "malicious").first()
        key = f"ip={ev.src_ip}"
        if ind and not _recent_alert(db, "R4-THREAT-INTEL-MATCH", ev.host, key):
            alerts.append(_raise(db, f"Activity from known-malicious IP {ev.src_ip}", "high",
                                 "R4-THREAT-INTEL-MATCH", ev.host,
                                 f"{key} matches indicator ({ind.malware or ind.campaign or 'malicious'})",
                                 source="threat-intel"))
    return alerts


def evaluate_posture(db: Session, host: str, telemetry: dict) -> list[Alert]:
    """Raise posture alerts from agent telemetry."""
    out = []
    if telemetry.get("defender_enabled") is False:
        if not _recent_alert(db, "R5-POSTURE-DEFENDER", host, f"host={host}"):
            out.append(_raise(db, f"Microsoft Defender disabled on {host}", "high", "R5-POSTURE-DEFENDER", host,
                              f"host={host} real-time protection is off", source="agent"))
    if telemetry.get("firewall_enabled") is False:
        if not _recent_alert(db, "R6-POSTURE-FIREWALL", host, f"host={host}"):
            out.append(_raise(db, f"Windows Firewall disabled on {host}", "medium", "R6-POSTURE-FIREWALL", host,
                              f"host={host} firewall profile is off", source="agent"))
    return out
