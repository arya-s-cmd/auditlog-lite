from __future__ import annotations
import json
from sqlalchemy.orm import Session
from sqlalchemy import text
from .models import AuditLog
from .utils import now_iso, hash_chain

def append_log(db: Session, actor: str, case_id: str, action: str, details: dict, ip: str | None, ua: str | None) -> AuditLog:
    prev = db.execute(text("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")).scalar()
    payload = {
        "ts": now_iso(), "actor": actor, "action": action, "case_id": case_id,
        "details": details, "prev_hash": prev or ""
    }
    h = hash_chain(prev, payload)
    row = AuditLog(ts=payload["ts"], actor=actor, action=action, case_id=case_id,
                   details_json=json.dumps(details, separators=(",", ":"), sort_keys=True),
                   prev_hash=prev, hash=h, ip=ip, ua=ua)
    db.add(row)
    return row

def verify_chain(db: Session) -> dict:
    rows = db.execute(text("SELECT id, ts, actor, action, case_id, details_json, prev_hash, hash FROM audit_log ORDER BY id ASC")).all()
    prev = None
    ok = True
    bad_at = None
    import json as _json
    for r in rows:
        payload = {"ts": r.ts, "actor": r.actor, "action": r.action, "case_id": r.case_id,
                   "details": _json.loads(r.details_json), "prev_hash": prev or ""}
        h = hash_chain(prev, payload)
        if h != r.hash:
            ok = False; bad_at = r.id; break
        prev = r.hash
    return {"ok": ok, "bad_at": bad_at, "count": len(rows)}
