import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from . import detection
from .database import Base, SessionLocal, engine, get_db
from .models import (Alert, Asset, AuditLog, CloudFinding, Control, EnrollmentToken, Event, Incident, Indicator,
                     SoarAction, User, Vulnerability, now)
from .security import (LOCKOUT_MINUTES, MAX_FAILED_LOGINS, ROLES, PERMISSIONS, audit, client_ip, create_access_token,
                       current_agent, current_user, hash_password, hash_token, new_token, password_policy_error,
                       rate_limit, require, verify_password)

app = FastAPI(title="CyberFusion API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:8080").split(","),
    allow_methods=["*"], allow_headers=["*"],
)

SEV_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}
SEV_ORDER = ["critical", "high", "medium", "low"]


def aware(dt: datetime | None) -> datetime | None:
    """Normalise to UTC (SQLite returns naive values; PostgreSQL returns session-timezone values)."""
    if dt and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc) if dt else dt


def sev_from_cvss(cvss: float) -> str:
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"


def row(obj) -> dict:
    d = {c.name: getattr(obj, c.name) for c in obj.__table__.columns}
    d.pop("password_hash", None)
    d.pop("agent_token_hash", None)
    d.pop("token_hash", None)
    return d


def get_or_404(db: Session, model, id: int):
    obj = db.get(model, id)
    if not obj:
        raise HTTPException(404, f"{model.__name__} not found")
    return obj


@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    from .seed import seed
    db = SessionLocal()
    try:
        seed(db)
    finally:
        db.close()


@app.get("/api/health")
def health():
    return {"status": "ok", "time": now()}


# ======================================================================
# Authentication (dashboard)
# ======================================================================
class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    rate_limit(f"login:{ip}", 20)
    user = db.query(User).filter(User.username == body.username).first()
    if user and user.locked_until and aware(user.locked_until) > now():
        audit(db, body.username, "login_blocked_locked", ip=ip)
        raise HTTPException(423, "Account temporarily locked. Try again later.")
    if not user or not verify_password(body.password, user.password_hash):
        if user:
            user.failed_logins += 1
            if user.failed_logins >= MAX_FAILED_LOGINS:
                user.locked_until = now() + timedelta(minutes=LOCKOUT_MINUTES)
                user.failed_logins = 0
            db.commit()
        audit(db, body.username, "login_failed", ip=ip)
        raise HTTPException(401, "Invalid credentials")
    user.failed_logins = 0
    user.locked_until = None
    db.commit()
    audit(db, user.username, "login_success", ip=ip)
    return {"access_token": create_access_token(user), "token_type": "bearer",
            "user": {"username": user.username, "role": user.role}}


@app.get("/api/auth/me")
def me(user: User = Depends(current_user)):
    return {"username": user.username, "role": user.role,
            "permissions": [p for p, roles in PERMISSIONS.items() if user.role in roles]}


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str
    role: Literal["admin", "analyst", "vuln_analyst", "auditor", "readonly"]


@app.get("/api/users")
def list_users(db: Session = Depends(get_db), _: User = Depends(require("manage_users"))):
    return [row(u) for u in db.query(User).order_by(User.id)]


@app.post("/api/users", status_code=201)
def create_user(body: UserIn, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require("manage_users"))):
    err = password_policy_error(body.password)
    if err:
        raise HTTPException(422, err)
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, "Username already exists")
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(u)
    db.commit()
    audit(db, admin.username, "user_created", body.username, f"role={body.role}", client_ip(request))
    return row(u)


class RoleIn(BaseModel):
    role: Literal["admin", "analyst", "vuln_analyst", "auditor", "readonly"]


@app.patch("/api/users/{uid}/role")
def change_role(uid: int, body: RoleIn, request: Request, db: Session = Depends(get_db),
                admin: User = Depends(require("manage_users"))):
    u = get_or_404(db, User, uid)
    if u.id == admin.id:
        raise HTTPException(400, "You cannot change your own role")
    old, u.role = u.role, body.role
    db.commit()
    audit(db, admin.username, "privilege_change", u.username, f"{old} -> {body.role}", client_ip(request))
    return row(u)


# ======================================================================
# Agent enrollment & telemetry
# ======================================================================
class EnrollTokenIn(BaseModel):
    label: str = ""
    valid_hours: int = Field(default=24, ge=1, le=168)


@app.post("/api/agents/enrollment-tokens", status_code=201)
def create_enrollment_token(body: EnrollTokenIn, request: Request, db: Session = Depends(get_db),
                            user: User = Depends(require("manage_assets"))):
    token = new_token("enr")
    db.add(EnrollmentToken(token_hash=hash_token(token), label=body.label,
                           expires_at=now() + timedelta(hours=body.valid_hours)))
    db.commit()
    audit(db, user.username, "enrollment_token_created", body.label, ip=client_ip(request))
    # Shown once; only the hash is stored.
    return {"enrollment_token": token, "expires_in_hours": body.valid_hours}


class EnrollIn(BaseModel):
    enrollment_token: str
    hostname: str = Field(max_length=128)
    os: str = ""
    ip: str = ""
    agent_version: str = ""


@app.post("/api/agents/enroll", status_code=201)
def enroll(body: EnrollIn, request: Request, db: Session = Depends(get_db)):
    ip = client_ip(request)
    rate_limit(f"enroll:{ip}", 10)
    tok = db.query(EnrollmentToken).filter(EnrollmentToken.token_hash == hash_token(body.enrollment_token)).first()
    if not tok or tok.used or aware(tok.expires_at) < now():
        audit(db, "agent", "agent_enroll_failed", body.hostname, "invalid, used or expired enrollment token", ip)
        raise HTTPException(401, "Invalid, used or expired enrollment token")
    agent_token = new_token("agt")
    asset = Asset(hostname=body.hostname, os=body.os, ip=body.ip, agent_version=body.agent_version,
                  agent_token_hash=hash_token(agent_token), last_seen=now())
    tok.used = True  # single use
    db.add(asset)
    db.commit()
    audit(db, "agent", "agent_enrolled", body.hostname, ip=ip)
    return {"agent_id": asset.id, "agent_token": agent_token}


class HeartbeatIn(BaseModel):
    hostname: str | None = None
    os: str | None = None
    ip: str | None = None
    agent_version: str | None = None
    telemetry: dict = Field(default_factory=dict)


@app.post("/api/agents/heartbeat")
def heartbeat(body: HeartbeatIn, asset: Asset = Depends(current_agent), db: Session = Depends(get_db)):
    for f in ("hostname", "os", "ip", "agent_version"):
        v = getattr(body, f)
        if v:
            setattr(asset, f, v[:128])
    if body.telemetry:
        if len(json.dumps(body.telemetry)) > 20_000:
            raise HTTPException(413, "Telemetry payload too large")
        asset.telemetry = body.telemetry
        detection.evaluate_posture(db, asset.hostname, body.telemetry)
    asset.last_seen = now()
    db.commit()
    return {"status": "ok", "server_time": now()}


class AgentEventIn(BaseModel):
    event_type: str = Field(max_length=64)
    user: str = ""
    src_ip: str = ""
    outcome: str = ""
    message: str = ""
    raw: dict = Field(default_factory=dict)


@app.post("/api/agents/events")
def agent_events(events: list[AgentEventIn], asset: Asset = Depends(current_agent), db: Session = Depends(get_db)):
    if len(events) > 500:
        raise HTTPException(413, "Max 500 events per request")
    created = 0
    for e in events:
        ev = Event(source=f"agent:{asset.hostname}", host=asset.hostname, **e.model_dump())
        db.add(ev)
        db.commit()
        detection.evaluate(db, ev)
        created += 1
    return {"accepted": created}


@app.post("/api/agents/{aid}/revoke")
def revoke_agent(aid: int, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require("manage_assets"))):
    a = get_or_404(db, Asset, aid)
    a.revoked = True
    db.commit()
    audit(db, user.username, "agent_revoked", a.hostname, ip=client_ip(request))
    return row(a)


# ======================================================================
# Assets
# ======================================================================
def asset_risk(db: Session, asset_id: int) -> int:
    vulns = db.query(Vulnerability).filter(Vulnerability.asset_id == asset_id,
                                           Vulnerability.status.in_(["open", "in_progress"])).all()
    raw = sum(SEV_WEIGHT[v.severity] * (1 + v.epss) for v in vulns)
    return min(100, int(raw * 2))


def asset_view(db: Session, a: Asset) -> dict:
    d = row(a)
    ls = aware(a.last_seen)
    d["status"] = ("revoked" if a.revoked else "isolated" if a.isolated else
                   "online" if ls and now() - ls < timedelta(minutes=5) else "offline")
    d["risk_score"] = asset_risk(db, a.id)
    d["open_vulns"] = db.query(Vulnerability).filter(Vulnerability.asset_id == a.id,
                                                    Vulnerability.status.in_(["open", "in_progress"])).count()
    return d


@app.get("/api/assets")
def list_assets(db: Session = Depends(get_db), _: User = Depends(require("view"))):
    return [asset_view(db, a) for a in db.query(Asset).order_by(Asset.id)]


@app.get("/api/assets/{aid}")
def get_asset(aid: int, db: Session = Depends(get_db), _: User = Depends(require("view"))):
    a = get_or_404(db, Asset, aid)
    d = asset_view(db, a)
    d["vulnerabilities"] = [row(v) for v in db.query(Vulnerability).filter(Vulnerability.asset_id == aid)]
    d["alerts"] = [row(x) for x in db.query(Alert).filter(Alert.host == a.hostname).order_by(Alert.id.desc()).limit(20)]
    return d


class CriticalityIn(BaseModel):
    criticality: Literal["low", "medium", "high", "critical"]


@app.patch("/api/assets/{aid}")
def update_asset(aid: int, body: CriticalityIn, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require("manage_assets"))):
    a = get_or_404(db, Asset, aid)
    a.criticality = body.criticality
    db.commit()
    audit(db, user.username, "asset_updated", a.hostname, f"criticality={body.criticality}", client_ip(request))
    return asset_view(db, a)


# ======================================================================
# Vulnerabilities  (Asset -> Vulnerability -> Severity -> Risk -> Remediation -> Verification)
# ======================================================================
class VulnIn(BaseModel):
    asset_id: int
    cve: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    title: str
    software: str = ""
    cvss: float = Field(ge=0, le=10)
    epss: float = Field(default=0, ge=0, le=1)
    remediation: str = ""
    source: str = "manual"


@app.get("/api/vulnerabilities")
def list_vulns(status: str | None = None, severity: str | None = None, db: Session = Depends(get_db),
               _: User = Depends(require("view"))):
    q = db.query(Vulnerability, Asset.hostname, Asset.criticality).join(Asset, Asset.id == Vulnerability.asset_id)
    if status:
        q = q.filter(Vulnerability.status == status)
    if severity:
        q = q.filter(Vulnerability.severity == severity)
    out = []
    for v, host, crit in q.order_by(Vulnerability.cvss.desc()):
        d = row(v)
        d["hostname"] = host
        # business risk: severity x exploit likelihood x asset criticality
        d["business_risk"] = round(v.cvss * (0.5 + v.epss) * {"low": 0.8, "medium": 1, "high": 1.2, "critical": 1.5}[crit], 1)
        out.append(d)
    return out


@app.post("/api/vulnerabilities", status_code=201)
def create_vuln(body: VulnIn, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require("manage_vulns"))):
    get_or_404(db, Asset, body.asset_id)
    v = Vulnerability(**body.model_dump(), severity=sev_from_cvss(body.cvss))
    db.add(v)
    db.commit()
    audit(db, user.username, "vulnerability_created", body.cve, f"asset={body.asset_id}", client_ip(request))
    return row(v)


class VulnStatusIn(BaseModel):
    status: Literal["open", "in_progress", "remediated", "verified"]


@app.patch("/api/vulnerabilities/{vid}")
def update_vuln(vid: int, body: VulnStatusIn, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require("manage_vulns"))):
    v = get_or_404(db, Vulnerability, vid)
    if body.status == "verified" and v.status != "remediated":
        raise HTTPException(400, "A vulnerability must be remediated before it can be verified")
    old, v.status = v.status, body.status
    db.commit()
    audit(db, user.username, "vulnerability_status", v.cve, f"{old} -> {body.status}", client_ip(request))
    return row(v)


class ScannerFinding(BaseModel):
    hostname: str
    cve: str
    title: str
    software: str = ""
    cvss: float = Field(ge=0, le=10)
    epss: float = 0
    remediation: str = ""


class ScannerImport(BaseModel):
    scanner: Literal["rapid7", "qualys", "tenable", "other"]
    findings: list[ScannerFinding]


@app.post("/api/integrations/scanner/import")
def scanner_import(body: ScannerImport, request: Request, db: Session = Depends(get_db),
                   user: User = Depends(require("manage_vulns"))):
    """Normalisation layer: Scanner -> Integration API -> CyberFusion -> Normalised finding."""
    added = skipped = 0
    for f in body.findings:
        asset = db.query(Asset).filter(Asset.hostname == f.hostname).first()
        if not asset:
            skipped += 1
            continue
        exists = db.query(Vulnerability).filter(Vulnerability.asset_id == asset.id, Vulnerability.cve == f.cve).first()
        if exists:
            continue
        db.add(Vulnerability(asset_id=asset.id, cve=f.cve, title=f.title, software=f.software, cvss=f.cvss,
                             epss=f.epss, severity=sev_from_cvss(f.cvss), remediation=f.remediation,
                             source=body.scanner))
        added += 1
    db.commit()
    audit(db, user.username, "scanner_import", body.scanner, f"added={added} skipped={skipped}", client_ip(request))
    return {"added": added, "skipped_unknown_asset": skipped}


# ======================================================================
# SIEM: events & alerts
# ======================================================================
class EventIn(BaseModel):
    source: str = Field(max_length=64)
    event_type: str = Field(max_length=64)
    host: str = ""
    user: str = ""
    src_ip: str = ""
    outcome: str = ""
    message: str = ""
    raw: dict = Field(default_factory=dict)


@app.post("/api/events", status_code=201)
def ingest_event(body: EventIn, db: Session = Depends(get_db), _: User = Depends(require("ingest"))):
    ev = Event(**body.model_dump())
    db.add(ev)
    db.commit()
    alerts = detection.evaluate(db, ev)
    return {"event_id": ev.id, "alerts_raised": [a.id for a in alerts]}


@app.get("/api/events")
def list_events(q: str | None = None, event_type: str | None = None, limit: int = 100,
                db: Session = Depends(get_db), _: User = Depends(require("view"))):
    query = db.query(Event)
    if event_type:
        query = query.filter(Event.event_type == event_type)
    if q:
        like = f"%{q}%"
        query = query.filter(Event.message.like(like) | Event.host.like(like) | Event.user.like(like) |
                             Event.src_ip.like(like))
    return [row(e) for e in query.order_by(Event.timestamp.desc()).limit(min(limit, 500))]


@app.get("/api/siem/rules")
def rules(_: User = Depends(require("view"))):
    return [
        {"id": "R1-BRUTE-FORCE", "name": "Repeated failed logins", "logic": ">=5 auth failures for one user in 10 min", "severity": "high"},
        {"id": "R2-FAIL-THEN-SUCCESS", "name": "Failed logins then success", "logic": ">=3 failures followed by a success in 10 min", "severity": "critical"},
        {"id": "R3-DEFENSE-EVASION", "name": "Security tooling disabled", "logic": "Defender/firewall disabled or audit log cleared", "severity": "high"},
        {"id": "R4-THREAT-INTEL-MATCH", "name": "Known-malicious source", "logic": "Event source IP matches a malicious indicator", "severity": "high"},
        {"id": "R5-POSTURE-DEFENDER", "name": "Defender disabled (agent)", "logic": "Agent telemetry reports real-time protection off", "severity": "high"},
        {"id": "R6-POSTURE-FIREWALL", "name": "Firewall disabled (agent)", "logic": "Agent telemetry reports firewall off", "severity": "medium"},
    ]


@app.get("/api/alerts")
def list_alerts(status: str | None = None, severity: str | None = None, db: Session = Depends(get_db),
                _: User = Depends(require("view"))):
    q = db.query(Alert)
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    return [row(a) for a in q.order_by(Alert.id.desc()).limit(300)]


class AlertStatusIn(BaseModel):
    status: Literal["new", "investigating", "closed"]


@app.patch("/api/alerts/{aid}")
def update_alert(aid: int, body: AlertStatusIn, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require("manage_alerts"))):
    a = get_or_404(db, Alert, aid)
    a.status = body.status
    db.commit()
    audit(db, user.username, "alert_status", str(aid), body.status, client_ip(request))
    return row(a)


@app.post("/api/alerts/{aid}/incident", status_code=201)
def alert_to_incident(aid: int, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require("manage_incidents"))):
    a = get_or_404(db, Alert, aid)
    if a.incident_id:
        raise HTTPException(409, "Alert is already linked to an incident")
    asset = db.query(Asset).filter(Asset.hostname == a.host).first()
    inc = Incident(title=a.title, severity=a.severity, detection_source=a.rule or a.source,
                   affected_assets=[a.host] if a.host else [], assigned_to=user.username,
                   timeline=[{"time": now().isoformat(), "by": user.username, "entry": f"Incident opened from alert #{a.id}"}],
                   evidence=[{"type": "alert", "ref": a.id, "summary": a.description}])
    db.add(inc)
    db.commit()
    a.incident_id, a.status = inc.id, "investigating"
    db.commit()
    audit(db, user.username, "incident_created", str(inc.id), f"from alert {a.id}", client_ip(request))
    return row(inc)


# ======================================================================
# Incident response
# ======================================================================
class IncidentIn(BaseModel):
    title: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    detection_source: str = "manual"
    affected_assets: list[str] = []
    assigned_to: str = ""


@app.get("/api/incidents")
def list_incidents(db: Session = Depends(get_db), _: User = Depends(require("view"))):
    return [row(i) for i in db.query(Incident).order_by(Incident.id.desc())]


@app.get("/api/incidents/{iid}")
def get_incident(iid: int, db: Session = Depends(get_db), _: User = Depends(require("view"))):
    inc = get_or_404(db, Incident, iid)
    d = row(inc)
    d["alerts"] = [row(a) for a in db.query(Alert).filter(Alert.incident_id == iid)]
    d["soar_actions"] = [row(s) for s in db.query(SoarAction).filter(SoarAction.incident_id == iid)]
    return d


@app.post("/api/incidents", status_code=201)
def create_incident(body: IncidentIn, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require("manage_incidents"))):
    inc = Incident(**body.model_dump(),
                   timeline=[{"time": now().isoformat(), "by": user.username, "entry": "Incident opened"}])
    db.add(inc)
    db.commit()
    audit(db, user.username, "incident_created", str(inc.id), ip=client_ip(request))
    return row(inc)


class IncidentUpdate(BaseModel):
    status: Literal["open", "investigating", "contained", "resolved"] | None = None
    containment_status: Literal["none", "in_progress", "contained"] | None = None
    remediation_status: Literal["none", "in_progress", "done"] | None = None
    assigned_to: str | None = None
    notes: str | None = None
    timeline_entry: str | None = None
    evidence: dict | None = None


@app.patch("/api/incidents/{iid}")
def update_incident(iid: int, body: IncidentUpdate, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require("manage_incidents"))):
    inc = get_or_404(db, Incident, iid)
    tl = list(inc.timeline)
    for f in ("status", "containment_status", "remediation_status", "assigned_to", "notes"):
        v = getattr(body, f)
        if v is not None and getattr(inc, f) != v:
            if f != "notes":
                tl.append({"time": now().isoformat(), "by": user.username, "entry": f"{f} changed to {v}"})
            setattr(inc, f, v)
    if body.timeline_entry:
        tl.append({"time": now().isoformat(), "by": user.username, "entry": body.timeline_entry})
    if body.evidence:
        inc.evidence = [*inc.evidence, body.evidence]
    inc.timeline = tl
    db.commit()
    audit(db, user.username, "incident_updated", str(iid), ip=client_ip(request))
    return row(inc)


# ======================================================================
# SOAR - every disruptive action needs a second person's approval
# ======================================================================
class SoarRequest(BaseModel):
    action: Literal["isolate_endpoint", "release_endpoint", "revoke_agent"]
    asset_id: int
    incident_id: int | None = None
    reason: str = Field(min_length=5)


@app.get("/api/soar")
def list_soar(db: Session = Depends(get_db), _: User = Depends(require("view"))):
    out = []
    for s, host in db.query(SoarAction, Asset.hostname).join(Asset, Asset.id == SoarAction.asset_id).order_by(SoarAction.id.desc()):
        d = row(s)
        d["hostname"] = host
        out.append(d)
    return out


@app.post("/api/soar", status_code=201)
def request_soar(body: SoarRequest, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require("request_response"))):
    get_or_404(db, Asset, body.asset_id)
    s = SoarAction(**body.model_dump(), requested_by=user.username)
    db.add(s)
    db.commit()
    audit(db, user.username, "soar_requested", f"{body.action}:{body.asset_id}", body.reason, client_ip(request))
    return row(s)


class Decision(BaseModel):
    decision: Literal["approve", "reject"]


@app.post("/api/soar/{sid}/decision")
def decide_soar(sid: int, body: Decision, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require("approve_response"))):
    s = get_or_404(db, SoarAction, sid)
    if s.status != "pending":
        raise HTTPException(409, f"Action already {s.status}")
    if s.requested_by == user.username:
        raise HTTPException(403, "Four-eyes rule: you cannot approve your own request")
    s.approved_by, s.decided_at = user.username, now()
    if body.decision == "reject":
        s.status = "rejected"
    else:
        asset = db.get(Asset, s.asset_id)
        if s.action == "isolate_endpoint":
            asset.isolated = True
        elif s.action == "release_endpoint":
            asset.isolated = False
        elif s.action == "revoke_agent":
            asset.revoked = True
        s.status = "executed"
        if s.incident_id:
            inc = db.get(Incident, s.incident_id)
            if inc:
                inc.timeline = [*inc.timeline, {"time": now().isoformat(), "by": user.username,
                                                "entry": f"{s.action} on {asset.hostname} approved and executed"}]
    db.commit()
    audit(db, user.username, f"soar_{body.decision}", f"{s.action}:{s.asset_id}", ip=client_ip(request))
    return row(s)


# ======================================================================
# Threat intelligence
# ======================================================================
class IndicatorIn(BaseModel):
    type: Literal["ip", "domain", "url", "hash"]
    value: str = Field(min_length=3, max_length=512)
    reputation: Literal["malicious", "suspicious", "benign", "unknown"] = "unknown"
    confidence: int = Field(default=50, ge=0, le=100)
    malware: str = ""
    campaign: str = ""


@app.get("/api/intel")
def list_intel(db: Session = Depends(get_db), _: User = Depends(require("view"))):
    return [row(i) for i in db.query(Indicator).order_by(Indicator.id.desc())]


@app.post("/api/intel", status_code=201)
def add_indicator(body: IndicatorIn, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require("manage_intel"))):
    ind = Indicator(**body.model_dump())
    db.add(ind)
    db.commit()
    audit(db, user.username, "indicator_added", body.value, ip=client_ip(request))
    return row(ind)


@app.get("/api/intel/lookup")
def lookup(value: str, db: Session = Depends(get_db), _: User = Depends(require("view"))):
    """Enrich an indicator: stored reputation plus every place it has been observed locally."""
    ind = db.query(Indicator).filter(Indicator.value == value).first()
    seen = db.query(Event).filter((Event.src_ip == value) | (Event.host == value) | (Event.message.contains(value))).count()
    hosts = [h for (h,) in db.query(Event.host).filter(Event.src_ip == value).distinct()]
    return {"value": value, "known": ind is not None, "indicator": row(ind) if ind else None,
            "local_sightings": seen, "hosts_contacted": hosts}


# ======================================================================
# Cloud security
# ======================================================================
class CloudIn(BaseModel):
    provider: Literal["azure", "aws", "gcp"]
    resource: str
    category: Literal["network_security", "access_control", "logging_monitoring", "encryption", "config_management"]
    title: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"


@app.get("/api/cloud")
def list_cloud(db: Session = Depends(get_db), _: User = Depends(require("view"))):
    return [row(c) for c in db.query(CloudFinding).order_by(CloudFinding.id.desc())]


@app.post("/api/cloud", status_code=201)
def add_cloud(body: CloudIn, request: Request, db: Session = Depends(get_db),
              user: User = Depends(require("manage_cloud"))):
    c = CloudFinding(**body.model_dump())
    db.add(c)
    db.commit()
    audit(db, user.username, "cloud_finding_added", body.resource, ip=client_ip(request))
    return row(c)


class CloudStatus(BaseModel):
    status: Literal["open", "resolved"]


@app.patch("/api/cloud/{cid}")
def update_cloud(cid: int, body: CloudStatus, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require("manage_cloud"))):
    c = get_or_404(db, CloudFinding, cid)
    c.status = body.status
    db.commit()
    audit(db, user.username, "cloud_finding_status", c.resource, body.status, client_ip(request))
    return row(c)


# ======================================================================
# Compliance: Finding -> Security control -> Framework -> Remediation
# ======================================================================
def open_findings_by_category(db: Session) -> dict[str, list[dict]]:
    f: dict[str, list[dict]] = {}

    def add(cat, kind, title, sev):
        f.setdefault(cat, []).append({"kind": kind, "title": title, "severity": sev})

    for v in db.query(Vulnerability).filter(Vulnerability.status.in_(["open", "in_progress"])):
        add("vulnerability_management", "vulnerability", f"{v.cve} - {v.title}", v.severity)
    for c in db.query(CloudFinding).filter(CloudFinding.status == "open"):
        add(c.category, "cloud", f"{c.provider.upper()}: {c.title}", c.severity)
    cat_map = {"R1": "access_control", "R2": "access_control", "R3": "endpoint_protection",
               "R4": "network_security", "R5": "endpoint_protection", "R6": "endpoint_protection"}
    for a in db.query(Alert).filter(Alert.status != "closed"):
        add(cat_map.get(a.rule[:2], "logging_monitoring"), "alert", a.title, a.severity)
    for i in db.query(Incident).filter(Incident.status != "resolved"):
        add("incident_response", "incident", i.title, i.severity)
    return f


REMEDIATION = {
    "vulnerability_management": "Patch or mitigate open vulnerabilities, then verify the fix.",
    "access_control": "Enforce MFA, review credentials under attack, tighten privileges.",
    "endpoint_protection": "Re-enable Defender and the host firewall; deploy via Group Policy/Intune.",
    "network_security": "Block malicious sources and close publicly exposed services.",
    "logging_monitoring": "Enable audit logging and forward logs to the SIEM.",
    "encryption": "Enable encryption at rest and enforce TLS in transit.",
    "config_management": "Remediate insecure configuration against a hardened baseline.",
    "incident_response": "Resolve open incidents and complete post-incident review.",
}


@app.get("/api/compliance")
def compliance(db: Session = Depends(get_db), _: User = Depends(require("view_compliance"))):
    findings = open_findings_by_category(db)
    frameworks: dict[str, dict] = {}
    for c in db.query(Control).order_by(Control.framework, Control.control_id):
        fw = frameworks.setdefault(c.framework, {"framework": c.framework, "controls": [], "passing": 0})
        related = findings.get(c.category, [])
        status = "failing" if related else "passing"
        fw["passing"] += status == "passing"
        fw["controls"].append({"control_id": c.control_id, "title": c.title, "category": c.category, "status": status,
                               "findings": related[:10], "finding_count": len(related),
                               "remediation": REMEDIATION.get(c.category, "") if related else ""})
    for fw in frameworks.values():
        total = len(fw["controls"])
        fw["total"] = total
        fw["score"] = round(100 * fw["passing"] / total) if total else 0
    return list(frameworks.values())


# ======================================================================
# Audit trail
# ======================================================================
@app.get("/api/audit")
def get_audit(limit: int = 200, db: Session = Depends(get_db), _: User = Depends(require("view_audit"))):
    return [row(a) for a in db.query(AuditLog).order_by(AuditLog.id.desc()).limit(min(limit, 1000))]


@app.get("/api/audit/verify")
def verify_audit(db: Session = Depends(get_db), _: User = Depends(require("view_audit"))):
    """Walk the hash chain; any edited or deleted row breaks it."""
    prev = "0" * 64
    for a in db.query(AuditLog).order_by(AuditLog.id):
        ts = aware(a.timestamp).isoformat()
        payload = f"{prev}|{a.actor}|{a.action}|{a.target}|{a.detail}|{a.ip}|{ts}"
        if a.prev_hash != prev or a.hash != hashlib.sha256(payload.encode()).hexdigest():
            return {"valid": False, "broken_at": a.id}
        prev = a.hash
    return {"valid": True, "entries": db.query(AuditLog).count()}


# ======================================================================
# Dashboard
# ======================================================================
@app.get("/api/dashboard")
def dashboard(db: Session = Depends(get_db), _: User = Depends(require("view"))):
    assets = db.query(Asset).all()
    online = sum(1 for a in assets if not a.revoked and aware(a.last_seen) and now() - aware(a.last_seen) < timedelta(minutes=5))
    open_v = db.query(Vulnerability).filter(Vulnerability.status.in_(["open", "in_progress"]))
    sev_counts = {s: open_v.filter(Vulnerability.severity == s).count() for s in SEV_ORDER}
    alerts_open = db.query(Alert).filter(Alert.status != "closed")
    alert_sev = {s: alerts_open.filter(Alert.severity == s).count() for s in SEV_ORDER}
    asset_scores = sorted(({"id": a.id, "hostname": a.hostname, "risk_score": asset_risk(db, a.id),
                            "criticality": a.criticality} for a in assets), key=lambda x: -x["risk_score"])
    # organisation risk: weighted open exposure, capped at 100
    exposure = sum(SEV_WEIGHT[s] * n for s, n in sev_counts.items()) + 2 * sum(SEV_WEIGHT[s] * n for s, n in alert_sev.items())
    risk = min(100, int(exposure * 1.5))

    # 7-day trend of alerts and events
    today = now().replace(hour=0, minute=0, second=0, microsecond=0)
    trend = []
    for d in range(6, -1, -1):
        start, end = today - timedelta(days=d), today - timedelta(days=d - 1)
        trend.append({"day": start.strftime("%a"),
                      "alerts": db.query(Alert).filter(Alert.created_at >= start, Alert.created_at < end).count(),
                      "events": db.query(Event).filter(Event.timestamp >= start, Event.timestamp < end).count()})
    return {
        "active_endpoints": online, "total_endpoints": len(assets),
        "critical_vulnerabilities": sev_counts["critical"], "vulnerabilities_by_severity": sev_counts,
        "open_alerts": alerts_open.count(), "alerts_by_severity": alert_sev,
        "open_incidents": db.query(Incident).filter(Incident.status != "resolved").count(),
        "pending_approvals": db.query(SoarAction).filter(SoarAction.status == "pending").count(),
        "high_risk_assets": [a for a in asset_scores if a["risk_score"] >= 50][:5],
        "top_assets": asset_scores[:5], "risk_score": risk, "trend": trend,
        "endpoint_health": {"online": online, "offline": len(assets) - online - sum(1 for a in assets if a.revoked),
                            "revoked": sum(1 for a in assets if a.revoked)},
        "recent_alerts": [row(a) for a in db.query(Alert).order_by(Alert.id.desc()).limit(6)],
    }
