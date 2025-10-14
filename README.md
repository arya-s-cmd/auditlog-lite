# Tamper-Evident Audit Logging (RBAC, PII-Safe Exports)

[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Security](https://img.shields.io/badge/security-hash--chained%20%7C%20append--only-blue.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](#)

A security-first logging system that records **who did what, when, and from where**—and makes silent edits or deletions **detectable**. It enforces **least-privilege access**, applies **PII redaction** on exports, and generates **access-activity reports** for audits.

---

## Why This Exists

Organizations handling sensitive cases (fraud, cybercrime, HR, healthcare) need to **prove** integrity of their timelines and **control** who can see what. Traditional logs are:
- Editable without detection (no integrity guarantees)
- Over-privileged (no least-privilege enforcement)
- Leaky (exports reveal PII without need-to-know)
- Fragmented (no consolidated view of **who accessed what**)

**This project provides** a tamper-evident, access-controlled, export-safe audit trail that is easy to deploy and verify.

---

## What This System Guarantees

- **Tamper-evidence:** Write-once, hash-chained entries (`prev_hash → hash`). Any mid-chain change breaks verification.
- **Append-only storage:** DB triggers prevent `UPDATE`/`DELETE` on the audit table.
- **Least-privilege RBAC:** Roles (admin, auditor, investigator) mapped to precise permissions.
- **PII-safe exports:** JSON/CSV exports redact names/emails/phones/notes unless the caller has explicit permission.
- **Provenance clarity:** Every sensitive endpoint call writes an **access log** entry (who, when, which endpoint, params).
- **Verifiable state:** A `/verify/chain` endpoint recomputes the entire chain and pinpoints the first corrupted record.

---

## Feature Overview

- **Write API** to append immutable entries with contextual `details` (captures IP/UA).
- **Read API** with automatic field masking based on role.
- **Export API** (JSON/CSV) with enforced masking unless authorized.
- **Access reports** (per-user rollups, last-N events, endpoint heatmaps).
- **Retention controls** (env flags + recipes for archival/purge).
- **One-command deploy** via Docker Compose; optional Postgres.

---

## Architecture (At a Glance)

    +-----------+     HTTPS      +-----------------------+       +------------------+
    |  Browser  | <----------->  |     FastAPI Service   | ----> | SQLite/Postgres  |
    |  (React)  |                |  /log /export /verify |       | Append-only log  |
    +-----------+                +-----------------------+       +------------------+
          ^                              ^      ^
          | X-API-Key header             |      +--> Hash chain verification
          |                              +----------> RBAC (admin/auditor/investigator)
          +---------------------- Access Log (every protected endpoint hit)

**Data model (tables)**
- `audit_log(id, ts, actor, action, case_id, details_json, prev_hash, hash, ip, ua)`
- `users(id, email, role, api_key)` *(demo keys for local run)*
- `access_log(id, ts, actor, endpoint, params_json)`

---

## Security Controls

1. **Immutability**
   - Database triggers reject `UPDATE`/`DELETE` on `audit_log`.

2. **Hash chain**
   - `hash = SHA256(prev_hash + canonical_payload_json)`; canonical JSON uses sorted keys + stable separators.

3. **RBAC (least-privilege)**
   - `admin`: `write`, `read`, `export_unmasked`, `report`
   - `auditor`: `read`, `export_unmasked`, `report`
   - `investigator`: `write`, `read`, `export_masked`

4. **Masked reads/exports**
   - If a role lacks unmasked permission, PII fields (`name`, `email`, `phone`, `address`, `note`) are replaced with tokens.

5. **Access logging**
   - Every protected endpoint writes an `access_log` entry (user, endpoint, timestamp, params).

6. **Verification**
   - `/verify/chain` recomputes hashes end-to-end; returns `{ ok, bad_at, count }`.

> ❗ **Demo** uses API keys for simplicity. **Production:** use JWT/OIDC, rotate secrets, and restrict DB access.

---

## Quickstart (Local, Docker)

**Prereqs:** Docker Desktop/Engine; ports `8000` and `5173` free.

    docker compose up --build
    # UI         → http://localhost:5173
    # API docs   → http://localhost:8000/docs

**Demo API keys** (use as `X-API-Key` header):

- `ADMIN_DEMO_KEY` — full access  
- `AUDITOR_DEMO_KEY` — read + unmasked export  
- `INVESTIGATOR_DEMO_KEY` — write/read, masked only  

Data persists in the Docker volume. Reset with:

    docker compose down -v

---

## API Quick Tour

1) **Append a log entry**

    curl -X POST http://localhost:8000/log/write \
      -H "Content-Type: application/json" \
      -H "X-API-Key: INVESTIGATOR_DEMO_KEY" \
      -d '{
            "case_id":"CASE-5555",
            "action":"note_added",
            "details":{"note":"Docs reviewed","email":"alice@example.com","+meta":"ok"}
          }'

2) **List logs** (masked if not admin/auditor)

    curl -H "X-API-Key: INVESTIGATOR_DEMO_KEY" http://localhost:8000/log/list

3) **Export logs** (JSON/CSV)

    # Masked JSON (always allowed)
    curl -X POST http://localhost:8000/export/logs \
      -H "Content-Type: application/json" -H "X-API-Key: INVESTIGATOR_DEMO_KEY" \
      -d '{"mask": true, "format": "json"}'

    # Unmasked JSON (admin/auditor only)
    curl -X POST http://localhost:8000/export/logs \
      -H "Content-Type: application/json" -H "X-API-Key: ADMIN_DEMO_KEY" \
      -d '{"mask": false, "format": "json"}'

    # Masked CSV
    curl -X POST http://localhost:8000/export/logs \
      -H "Content-Type: application/json" -H "X-API-Key: INVESTIGATOR_DEMO_KEY" \
      -d '{"mask": true, "format": "csv"}'

4) **Verify the chain**

    curl http://localhost:8000/verify/chain
    # → {"ok": true, "bad_at": null, "count": <N>}

5) **Access reports** (admin/auditor)

    # Top endpoints and counts
    curl -H "X-API-Key: ADMIN_DEMO_KEY" http://localhost:8000/reports/endpoints

    # Per-user recent activity
    curl -H "X-API-Key: ADMIN_DEMO_KEY" "http://localhost:8000/reports/user?email=user@example.com&limit=50"

    # Last N access events (global)
    curl -H "X-API-Key: ADMIN_DEMO_KEY" "http://localhost:8000/reports/last?limit=100"

---

## Configuration

**Environment variables**
- `DB_URL` — SQLAlchemy database URL (default: `sqlite:///./app.db`)
- `HASH_ALGO` — hashing algorithm (`sha256` default)
- `EXPORT_MAX_ROWS` — cap for export size (e.g., `100000`)
- `REDACT_FIELDS` — comma-sep list of PII fields to mask (default: `name,email,phone,address,note`)
- `DEMO_KEYS_ENABLED` — `true|false` (disable in production)

**Ports**
- API: `8000`
- UI:  `5173`

---

## Endpoints (Summary)

- `POST /log/write` — append audit entry  
- `GET  /log/list` — list entries (masked by role)  
- `POST /export/logs` — export JSON/CSV (`mask: bool`)  
- `GET  /verify/chain` — verify hash chain  
- `GET  /reports/endpoints` — endpoint usage rollup  
- `GET  /reports/user` — per-user recent activity  
- `GET  /reports/last` — last N access events

Swagger UI: **`/docs`**

---

## RBAC Matrix

| Capability          | admin | auditor | investigator |
|---------------------|:-----:|:-------:|:------------:|
| Write logs          |  ✅   |   ❌    |      ✅      |
| Read logs           |  ✅   |   ✅    |      ✅      |
| Export (unmasked)   |  ✅   |   ✅    |      ❌      |
| Export (masked)     |  ✅   |   ✅    |      ✅      |
| Access reports      |  ✅   |   ✅    |      ❌      |
| Verify chain        |  ✅   |   ✅    |      ✅      |

---

## Roadmap (Optional)

- Cryptographic anchoring (daily Merkle root published externally)
- Signed exports (detached signatures + verification CLI)
- S3/GCS archival with object lock
- Fine-grained row-level permissions (case-scoped RBAC)

---

## License

[MIT License](LICENSE)

---

**Built for teams that need evidence that stands up to scrutiny.**
