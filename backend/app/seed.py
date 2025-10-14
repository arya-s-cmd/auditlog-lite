from __future__ import annotations
from sqlalchemy.orm import Session
from .db import SessionLocal, engine, Base, init_immutability
from .models import User
from .audit import append_log

def seed():
    Base.metadata.create_all(bind=engine); init_immutability()
    db: Session = SessionLocal()
    if db.query(User).count()==0:
        db.add_all([
            User(email="admin@example.com", role="admin", api_key="ADMIN_DEMO_KEY"),
            User(email="auditor@example.com", role="auditor", api_key="AUDITOR_DEMO_KEY"),
            User(email="investigator@example.com", role="investigator", api_key="INVESTIGATOR_DEMO_KEY"),
        ])
        db.commit()
    for i in range(4):
        append_log(db, actor="system@seed", case_id=f"CASE-{1000+i}", action="create_case",
                   details={"note":"Initial case created", "email":"alice@example.com","phone":"+91 9876543210"}, ip=None, ua=None)
    db.commit(); db.close()

if __name__ == "__main__":
    seed()
