from __future__ import annotations
import re, json, hashlib, datetime

PII_EMAIL = re.compile(r'([A-Za-z0-9._%+-])([A-Za-z0-9._%+-]*)(@[A-Za-z0-9.-]+)')
PII_PHONE = re.compile(r'(\+?\d)[\d\s-]{6,}\d')
PII_NAME  = re.compile(r'\b([A-Z])[a-z]+\s([A-Z])[a-z]+\b')

def mask_text(s: str) -> str:
    if not s: return s
    s = PII_EMAIL.sub(lambda m: m.group(1)+"***"+m.group(3), s)
    s = PII_PHONE.sub(lambda m: m.group(1)+"*******", s)
    s = PII_NAME.sub(lambda m: f"{m.group(1)}*** {m.group(2)}***", s)
    return s

def now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat()+"Z"

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def hash_chain(prev_hash: str | None, payload: dict) -> str:
    msg = (prev_hash or "") + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256_hex(msg)
