"""Approval gates: a human code, bound to the exact payload hash.

The code is delivered only through the operator's Telegram bot. Reusing an approved
gate requires an identical payload — a changed recipient/amount/domain is a new gate.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets

from . import config, db, notify, policy
from .jsonio import Denied, Gate
from .log import get_logger

log = get_logger("gates")


def _hash(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def _ttl() -> int:
    return int(policy.limits().get("gate_ttl_minutes", 720))


def pending_for(payload: dict) -> dict | None:
    return db.one("SELECT * FROM gates WHERE payload_hash=? AND status='pending' ORDER BY id DESC",
                  (_hash(payload),))


def _hash_code(code: str, salt: str) -> str:
    """Salted SHA-256 of a gate code. Only the hash is ever stored/compared —
    the plaintext code is never written to the DB (R4)."""
    return hashlib.sha256(f"{salt}:{code}".encode()).hexdigest()


def create(kind: str, summary: str, payload: dict) -> int:
    existing = pending_for(payload)
    if existing:
        return int(existing["id"])
    code = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6))
    salt = secrets.token_hex(16)
    gid = db.execute(
        "INSERT INTO gates(kind,summary,payload,payload_hash,code_hash,code_salt,code,created_at)"
        " VALUES(?,?,?,?,?,?,NULL,?)",
        (kind, summary, json.dumps(payload, default=str), _hash(payload),
         _hash_code(code, salt), salt, db.now()))
    db.event("gate", f"#{gid} {kind}: {summary[:160]}", payload.get("identity_id"), level="warn")
    notify.send(notify.gate_message(gid, kind, summary, code), silent=False)
    return gid


def require(kind: str, summary: str, payload: dict) -> None:
    """Gate unless an identical approved payload is still fresh, else raise Gate."""
    p = {**payload, "_kind": kind} if not payload.get("_kind") else payload
    h = _hash(p)
    with db.db() as con:
        r = con.execute("SELECT * FROM gates WHERE payload_hash=? AND status='approved' ORDER BY id DESC", (h,)).fetchone()
        if r:
            con.execute("UPDATE gates SET status='used', decided_at=? WHERE id=?", (db.now(), r["id"]))
            return
    gid = create(kind, summary, p)
    raise Gate(f"approval #{gid} required — {summary}")


def _check_code(gid: int, code: str) -> dict:
    r = db.one("SELECT * FROM gates WHERE id=?", (gid,))
    if not r:
        raise Denied(f"gate #{gid} not found")
    if r["status"] != "pending":
        raise Denied(f"gate #{gid} already {r['status']}")
    if not code:
        # A missing/empty code is a wrong code, not a crash (integration fix:
        # callers that used to read the plaintext code from the DB now get NULL).
        raise Denied(f"wrong code for gate #{gid}")
    given = code.strip().upper()
    salt = r.get("code_salt")
    if salt:
        ok = hmac.compare_digest(_hash_code(given, salt), r.get("code_hash") or "")
    elif r.get("code_hash"):
        # Legacy gates created before salted hashing: unsalted SHA-256 only.
        # Their plaintext `code` column is NULLed by the db migration, so this
        # still never compares plaintext.
        ok = hmac.compare_digest(hashlib.sha256(given.encode()).hexdigest(), r["code_hash"])
    else:
        ok = False
    if not ok:
        raise Denied(f"wrong code for gate #{gid}")
    return r


def approve(gid: int, code: str, *, persist_domain: bool = False) -> dict:
    """Approve a pending gate. The approval itself is one-time (consume/require
    mark it used); whether the gate's domain ALSO joins the permanent domain
    allowlist depends on the active mode (see policy.persist_domain_allowed):

    safe      never persisted — the approval covers this one action only.
    balanced  persisted only when the gate payload opts in (persist_domain: true)
              or the operator passes persist_domain=True here
              (`aa gate approve --persist-domain`).
    turbo     persisted (auto-allowlist is a turbo feature) and logged.
    """
    r = _check_code(gid, code)
    db.execute("UPDATE gates SET status='approved', decided_at=? WHERE id=?", (db.now(), gid))
    db.event("gate", f"#{gid} approved", level="info")
    try:
        payload = json.loads(r["payload"] or "{}")
    except ValueError:
        payload = {}
    persisted = False
    if payload.get("domain"):
        if policy.persist_domain_allowed({**payload, "persist_domain":
                                          bool(payload.get("persist_domain") or persist_domain)}):
            policy.allow_domain(payload["domain"])
            persisted = True
            log.info("gate #%s approved: domain %s added to the permanent allowlist "
                     "(mode=%s)", gid, payload["domain"], policy.mode())
        else:
            log.info("gate #%s approved (one-time only): domain %s NOT added to the "
                     "allowlist (mode=%s, no persist_domain opt-in)",
                     gid, payload["domain"], policy.mode())
    if payload.get("quest_yaml"):
        db.execute("UPDATE quests SET status='pending', updated_at=? WHERE id=?", (db.now(), payload["quest_id"]))
    return {"gate": gid, "status": "approved", "kind": r["kind"], "domain_persisted": persisted}


def reject(gid: int, reason: str = "") -> dict:
    db.execute("UPDATE gates SET status='rejected', decided_at=? WHERE id=?", (db.now(), gid))
    if reason:
        db.execute("UPDATE gates SET summary=summary||? WHERE id=?", (f" (reject: {reason})", gid))
    db.event("gate", f"#{gid} rejected {reason}")
    return {"gate": gid, "status": "rejected"}


def consume(payload: dict) -> dict | None:
    candidates = [payload]
    if not payload.get("_kind"):
        candidates.append({**payload, "_kind": "tx"})
    with db.db() as con:
        r = None
        for p in candidates:
            r = con.execute("SELECT id,created_at FROM gates WHERE payload_hash=? AND status='approved'"
                            " ORDER BY id DESC", (_hash(p),)).fetchone()
            if r and _age_min(r["created_at"]) <= _ttl():
                break
            r = None
        if not r:
            return None
        con.execute("UPDATE gates SET status='used' WHERE id=?", (r["id"],))
        return {"gate": r["id"]}


def list_gates(status: str = "pending") -> list[dict]:
    out = db.rows("SELECT id,kind,summary,status,created_at FROM gates WHERE status=? ORDER BY id DESC LIMIT 50",
                  (status,))
    for g in out:
        age = _age_min(g["created_at"])
        g["age_min"] = age
        g["expired"] = age > _ttl()
    return out


def _age_min(ts: str) -> int:
    import datetime as dt

    try:
        t = dt.datetime.fromisoformat(ts)
    except ValueError:
        return 0
    return int((dt.datetime.now(dt.timezone.utc) - t).total_seconds() / 60)


def expire_old() -> int:
    cutoff = _ttl()
    n = 0
    for g in db.rows("SELECT id FROM gates WHERE status='pending'"):
        if _age_min(db.one("SELECT created_at FROM gates WHERE id=?", (g["id"],))["created_at"]) > cutoff:
            db.execute("UPDATE gates SET status='expired' WHERE id=?", (g["id"],))
            n += 1
    return n


def poll_telegram() -> dict:
    """Ingest `approve <id> <CODE>` / `reject <id>` / `mode ...` from the owner only."""
    token, owner = config.env("TG_REPORT_BOT_TOKEN"), config.env("TG_OWNER_USER_ID")
    if not (token and owner):
        return {"updated": {}, "note": "TG_OWNER_USER_ID/TG_REPORT_BOT_TOKEN unset"}
    import requests

    state_file = config.DATA_DIR / "tg_offset.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else {"offset": 0}
    r = requests.get(f"https://api.telegram.org/bot{token}/getUpdates",
                     params={"offset": state["offset"], "timeout": 0,
                             "allowed_updates": '["message"]'}, timeout=20).json()
    changed: dict = {}
    for upd in r.get("result", []):
        state["offset"] = upd["update_id"] + 1
        msg = upd.get("message") or {}
        if str((msg.get("from") or {}).get("id")) != str(owner):
            continue
        parts = (msg.get("text") or "").strip().lstrip("/").split()
        if not parts:
            continue
        cmd = parts[0].lower()
        if cmd == "approve" and len(parts) == 3 and parts[1].isdigit():
            try:
                changed[parts[1]] = approve(int(parts[1]), parts[2])["status"]
            except SystemExit as e:
                changed[parts[1]] = str(e)
        elif cmd == "reject" and len(parts) == 2 and parts[1].isdigit():
            changed[parts[1]] = reject(int(parts[1]))["status"]
        elif cmd == "mode" and len(parts) >= 2:
            try:
                changed["mode"] = policy.set_mode(parts[1])
            except SystemExit as e:
                changed["mode"] = str(e)
        elif cmd == "stop":
            config.KILL_FILE.touch()
            changed["kill"] = "on"
        elif cmd == "go":
            config.KILL_FILE.unlink(missing_ok=True)
            changed["kill"] = "off"
    state_file.write_text(json.dumps(state))
    return {"updated": changed}
