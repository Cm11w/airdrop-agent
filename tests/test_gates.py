import re
import secrets
from unittest import mock

import pytest

from aa.jsonio import Gate

_CODE_RE = re.compile(r"aa gate approve \d+ ([A-Z0-9]{6})")


def capture_code():
    """Intercept the code the way the operator receives it: via notify.send
    (Telegram/stderr). The code is never stored in the DB (R4)."""
    captured = {}

    def _capture(text, **kw):
        m = _CODE_RE.search(text)
        if m:
            captured["code"] = m.group(1)
        return False

    return captured, _capture


def make(payload=None):
    from aa import gates

    payload = payload if payload is not None else {"rand": secrets.token_hex(4)}
    captured, _capture = capture_code()
    try:
        with mock.patch("aa.notify.send", _capture):
            gates.require("tx", "kirim 0.001", payload)
    except Gate:
        from aa import db

        g = db.one("SELECT * FROM gates ORDER BY id DESC LIMIT 1")
        g["code"] = captured.get("code")  # delivered via notify, never stored
        return g
    raise AssertionError("gates.require did not raise Gate")


def test_require_and_approve(home):
    from aa import gates

    g = make({"_kind": "tx", "chain": "sepolia"})
    assert g["status"] == "pending"
    assert len(g["code"]) == 6
    assert gates.consume({"_kind": "tx", "chain": "sepolia"}) is None
    gates.approve(g["id"], g["code"])
    out = gates.consume({"_kind": "tx", "chain": "sepolia"})
    assert out["gate"] == g["id"]


def test_approve_wrong_code(home):
    from aa import gates

    g = make({"_kind": "tx"})
    with pytest.raises(Exception):
        gates.approve(g["id"], "000000")
    assert gates.list_gates()[0]["status"] == "pending"


def test_double_use(home):
    from aa import gates

    g = make({"a": 1})
    gates.approve(g["id"], g["code"])
    assert gates.consume({"a": 1})
    assert gates.consume({"a": 1}) is None


def test_reject(home):
    from aa import gates

    g = make({"b": 2})
    gates.reject(g["id"])
    assert gates.consume({"b": 2}) is None


def test_expired_not_usable(home, monkeypatch):
    from aa import gates

    g = make({"c": 3})
    gates.approve(g["id"], g["code"])
    monkeypatch.setattr(gates, "_ttl", lambda: -1)
    assert gates.consume({"c": 3}) is None


def test_kill_blocks_require(home):
    from aa import gates, guard

    guard.kill("test")
    with pytest.raises(Exception):
        gates.require("tx", "x", {"z": 9})
    guard.unkill()
    assert make({"d": 4})


# ---------- R4: hash-only gate codes ----------

def test_create_stores_no_plaintext(home):
    import hashlib

    from aa import db, gates

    g = make({"r4": 1})
    row = db.one("SELECT * FROM gates WHERE id=?", (g["id"],))
    assert row["code"] is None, "plaintext gate code must never be stored"
    assert row["code_hash"], "salted hash must be stored"
    assert row["code_salt"], "per-gate salt must be stored"
    assert row["code_hash"] == hashlib.sha256(
        f"{row['code_salt']}:{g['code']}".encode()).hexdigest()
    assert g["code"] not in (row["code_hash"] or "")


def test_salted_hashes_differ_per_gate(home):
    from aa import gates

    assert gates._hash_code("ABCDEF", "salt-one") != gates._hash_code("ABCDEF", "salt-two")
    assert gates._hash_code("ABCDEF", "salt-one") == gates._hash_code("ABCDEF", "salt-one")


def test_legacy_plaintext_nulled_by_migration(home):
    import hashlib

    from aa import db, gates

    # Simulate a pre-fix row: plaintext code + unsalted hash.
    legacy_code = "ABCDEF"
    db.execute(
        "INSERT INTO gates(kind,summary,payload,payload_hash,code_hash,code_salt,code,created_at)"
        " VALUES(?,?,?,?,?,?,?,?)",
        ("tx", "legacy", "{}", "hash", hashlib.sha256(legacy_code.encode()).hexdigest(),
         None, legacy_code, db.now()))
    gid = db.one("SELECT id FROM gates ORDER BY id DESC LIMIT 1")["id"]
    # Any db access runs the migration: plaintext must be gone...
    row = db.one("SELECT * FROM gates WHERE id=?", (gid,))
    assert row["code"] is None
    # ...but the gate must still be approvable via its (unsalted) hash.
    assert gates.approve(gid, legacy_code)["status"] == "approved"


def test_db_file_mode_0600(home):
    import stat

    from aa import db

    db.one("SELECT 1")
    assert stat.S_IMODE(db.DB_PATH.stat().st_mode) == 0o600
