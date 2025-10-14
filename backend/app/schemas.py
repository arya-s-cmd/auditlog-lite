from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, Any, Dict, List

class LogIn(BaseModel):
    case_id: str
    action: str
    details: Dict[str, Any] = Field(default_factory=dict)

class LogOut(BaseModel):
    id: int
    ts: str
    actor: str
    action: str
    case_id: str
    details: Dict[str, Any]
    hash: str
    prev_hash: Optional[str] = None

class ExportRequest(BaseModel):
    mask: bool = True
    format: str = "json"

class ReportOut(BaseModel):
    by_user: Dict[str, int]
    recent: List[Dict[str, Any]]
    total: int
