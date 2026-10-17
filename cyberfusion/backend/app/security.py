import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import Asset, AuditLog, User

SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_urlsafe(48)  # set SECRET_KEY in production
ACCESS_TOKEN_MINUTES = int(os.getenv("ACCESS_TOKEN_MINUTES", "30"))
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
ALGO = "HS256"

ROLES = ["admin", "analyst", "vuln_analyst", "auditor", "readonly"]

# permission -> roles allowed
PERMISSIONS = {
    "view": ["admin", "analyst", "vuln_analyst", "auditor", "readonly"],
    "manage_alerts": ["admin", "analyst"],
    "manage_incidents": ["admin", "analyst"],
    "request_response": ["admin", "analyst"],
    "approve_response": ["admin"],
    "manage_vulns": ["admin", "vuln_analyst"],
    "manage_intel": ["admin", "analyst"],
    "manage_cloud": ["admin", "analyst"],
    "manage_assets": ["admin", "vuln_analyst"],
    "manage_users": ["admin"],
    "view_audit": ["admin", "auditor"],
    "view_compliance": ["admin", "auditor", "analyst", "vuln_analyst"],
    "ingest": ["admin", "analyst"],
}

bearer = HTTPBearer(auto_error=False)


# ---------- passwords & tokens ----------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, dk = stored.split("$")
        new = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310_000)
        return hmac.compare_digest(new.hex(), dk)
    except Exception:
        return False


def hash_token(token: str) -> str:
    """Agent/enrollment tokens are high-entropy, so a fast SHA-256 is appropriate; plaintext is never stored."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def create_access_token(user: User) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    return jwt.encode({"sub": user.username, "role": user.role, "exp": exp}, SECRET_KEY, algorithm=ALGO)


def password_policy_error(pw: str) -> str | None:
    if len(pw) < 12:
        return "Password must be at least 12 characters"
    if pw.lower() == pw or pw.upper() == pw or not any(c.isdigit() for c in pw):
        return "Password must mix upper/lower case and include a digit"
    return None


# ---------- rate limiting (in-memory, per key) ----------
_hits: dict[str, deque] = defaultdict(deque)


def rate_limit(key: str, limit: int, window: int = 60):
    now = time.time()
    q = _hits[key]
    while q and q[0] < now - window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded")
    q.append(now)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


# ---------- audit trail (hash-chained, append-only) ----------
def audit(db: Session, actor: str, action: str, target: str = "", detail: str = "", ip: str = ""):
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev = last.hash if last else "0" * 64
    ts = datetime.now(timezone.utc)
    payload = f"{prev}|{actor}|{action}|{target}|{detail}|{ip}|{ts.isoformat()}"
    entry = AuditLog(actor=actor, action=action, target=target, detail=detail, ip=ip,
                     prev_hash=prev, hash=hashlib.sha256(payload.encode()).hexdigest(), timestamp=ts)
    db.add(entry)
    db.commit()


# ---------- dependencies ----------
def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer),
                 db: Session = Depends(get_db)) -> User:
    if not creds:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    try:
        data = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGO])
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    user = db.query(User).filter(User.username == data["sub"]).first()
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown user")
    return user


def require(permission: str):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in PERMISSIONS[permission]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user
    return dep


def current_agent(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer),
                  db: Session = Depends(get_db)) -> Asset:
    """Every agent request is authenticated; being enrolled is never enough on its own."""
    if not creds:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing agent token")
    asset = db.query(Asset).filter(Asset.agent_token_hash == hash_token(creds.credentials)).first()
    if not asset or asset.revoked:
        audit(db, "agent", "agent_auth_failure", detail="invalid or revoked token", ip=client_ip(request))
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or revoked agent token")
    rate_limit(f"agent:{asset.id}", 120)
    return asset
