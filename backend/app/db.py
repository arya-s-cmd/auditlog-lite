from __future__ import annotations
import os
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base

DB_URL = os.getenv("DB_URL", "sqlite:///./audit.db")
connect_args = {"check_same_thread": False} if DB_URL.startswith("sqlite") else {}
engine = create_engine(DB_URL, echo=False, future=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

def init_immutability():
    if not DB_URL.startswith("sqlite"):
        return
    strict = os.getenv("STRICT_IMMUTABILITY", "0") == "1"
    try:
        with engine.begin() as conn:
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS audit_log(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                case_id TEXT NOT NULL,
                details_json TEXT NOT NULL,
                prev_hash TEXT,
                hash TEXT NOT NULL,
                ip TEXT,
                ua TEXT
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                role TEXT NOT NULL,
                api_key TEXT UNIQUE NOT NULL
            );
            """))
            conn.execute(text("""
            CREATE TABLE IF NOT EXISTS access_log(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                params_json TEXT
            );
            """))
            conn.execute(text("""
            CREATE TRIGGER IF NOT EXISTS audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only');
            END;
            """))
            conn.execute(text("""
            CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'audit_log is append-only');
            END;
            """))
    except Exception as e:
        msg = f"[immutability] failed to initialize sqlite immutability triggers/tables for DB_URL={DB_URL!r}: {e}"
        if strict:
            raise RuntimeError(msg) from e
        print(msg, file=sys.stderr)
        
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
