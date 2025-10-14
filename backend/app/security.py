from __future__ import annotations
from fastapi import Header, HTTPException, Request, Depends
from sqlalchemy.orm import Session
from .db import get_db
from .models import User, AccessLog
from .utils import now_iso
import json

ROLE_PERMS = {
    "admin": {"write", "read", "export_unmasked", "report"},
    "auditor": {"read", "export_unmasked", "report"},
    "investigator": {"write", "read", "export_masked"},
}

async def get_current_user(
    x_api_key: str | None = Header(None),
    db: Session = Depends(get_db),
) -> User:
    if not x_api_key:
        raise HTTPException(401, "X-API-Key required")
    user = db.query(User).filter(User.api_key == x_api_key).one_or_none()
    if not user:
        raise HTTPException(401, "Invalid API key")
    return user

def require_perms(required: set[str]):
    async def dep(user: User = Depends(get_current_user)) -> User:
        perms = ROLE_PERMS.get(user.role, set())
        if not required.issubset(perms):
            raise HTTPException(403, "Insufficient permissions")
        return user
    return dep

async def access_logger(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    db.add(AccessLog(
        ts=now_iso(),
        actor=user.email,
        endpoint=str(request.url.path),
        params_json=json.dumps(dict(request.query_params)),
    ))
    db.commit()
    return True  # placeholder dependency result
