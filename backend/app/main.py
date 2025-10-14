from __future__ import annotations
import json, os
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from .db import engine, Base, init_immutability, get_db
from .models import AuditLog, User
from .schemas import LogIn, LogOut, ExportRequest, ReportOut
from .security import get_current_user, require_perms, access_logger
from .audit import append_log, verify_chain
from .utils import mask_text, now_iso

app = FastAPI(title="Tamper-Evident Audit API")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    init_immutability()

@app.post("/log/write", response_model=LogOut)
async def log_write(payload: LogIn, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    entry = append_log(db, actor=user.email, case_id=payload.case_id, action=payload.action, details=payload.details,
                       ip=request.client.host if request.client else None, ua=request.headers.get("user-agent"))
    db.commit(); db.refresh(entry)
    return LogOut(id=entry.id, ts=entry.ts, actor=entry.actor, action=entry.action,
                  case_id=entry.case_id, details=payload.details, hash=entry.hash, prev_hash=entry.prev_hash)

@app.get("/log/list")
async def log_list(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_perms({"read"})),
    _al: bool = Depends(access_logger),
):
    rows = db.execute(text("SELECT id, ts, actor, action, case_id, details_json, prev_hash, hash FROM audit_log ORDER BY id DESC LIMIT 200")).all()
    def with_mask(d: str) -> dict:
        obj = json.loads(d)
        if user.role not in {"admin","auditor"}:
            for k in ["name","email","phone","address","note"]:
                if k in obj: obj[k] = mask_text(str(obj[k]))
        return obj
    out = [{"id":r.id, "ts":r.ts, "actor":r.actor, "action":r.action, "case_id":r.case_id,
            "details": with_mask(r.details_json), "prev_hash": r.prev_hash, "hash": r.hash} for r in rows]
    return out


@app.post("/export/logs")
async def export_logs(
    req: ExportRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_perms({"read"})),
    _al: bool = Depends(access_logger),
):
    allow_unmasked = user.role in {"admin","auditor"}
    mask = req.mask if allow_unmasked else True
    rows = db.execute(text("SELECT ts, actor, action, case_id, details_json, hash FROM audit_log ORDER BY id ASC")).all()
    def maybe_mask(d: str) -> dict:
        obj = json.loads(d)
        if mask:
            for k in list(obj.keys()):
                if k in {"name","email","phone","address","note"}:
                    obj[k] = mask_text(str(obj[k]))
        return obj
    data = [{"ts":r.ts, "actor":r.actor, "action":r.action, "case_id":r.case_id, "details": maybe_mask(r.details_json), "hash": r.hash} for r in rows]
    if req.format.lower()=="csv":
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ts","actor","action","case_id","details_json","hash"])
        for r in data:
            w.writerow([r["ts"], r["actor"], r["action"], r["case_id"], json.dumps(r["details"], separators=(",",":")), r["hash"]])
        return {"filename":"audit_export.csv","content":buf.getvalue()}
    return {"filename":"audit_export.json","content": json.dumps(data, separators=(",", ":"), ensure_ascii=False)}


@app.get("/verify/chain")
async def verify(db: Session = Depends(get_db)):
    return verify_chain(db)

@app.get("/reports/access", response_model=ReportOut)
async def access_report(
    db: Session = Depends(get_db),
    user: User = Depends(require_perms({"report"})),
    _al: bool = Depends(access_logger),
):
    rows = db.execute(text("SELECT actor, COUNT(*) c FROM access_log GROUP BY actor")).all()
    recent = db.execute(text("SELECT ts, actor, endpoint, params_json FROM access_log ORDER BY id DESC LIMIT 50")).all()
    return ReportOut(
        by_user={r.actor: r.c for r in rows},
        recent=[{"ts":r.ts, "actor":r.actor, "endpoint":r.endpoint, "params":json.loads(r.params_json or "{}")} for r in recent],
        total=sum(r.c for r in rows) if rows else 0
    )
