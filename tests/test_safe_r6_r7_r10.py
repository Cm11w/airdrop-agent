"""Safe-mode fixes for R6 (bad-domain navigation + drainer page text),
R7 (HTTPS/clipboard hardening) and R10 (no permanent allowlist from a
one-time approval).

Browser tests use a fake page — no Chromium is launched and nothing touches
the network.
"""
from types import SimpleNamespace

import pytest

from aa.jsonio import Denied, Gate

BAD_URL = "https://xn--uniswap-ycd.com/claim"  # punycode -> scam_check verdict bad
CLEAN_URL = "https://example.com/"
DRAINER_TEXT = "Enter your seed phrase to validate wallet and claim reward"
CLEAN_TEXT = "Welcome to Example. Connect your wallet to see your points."


class FakePage:
    def __init__(self, text=""):
        self.url = CLEAN_URL
        self._text = text
        self.goto_calls: list[str] = []

    async def goto(self, url, wait_until=None, timeout=None):
        self.goto_calls.append(url)
        self.url = url
        return None

    async def inner_text(self, selector):
        return self._text


@pytest.fixture
def fake_browser(monkeypatch):
    """A Browser with a fake page and the Cloudflare layer stubbed out."""
    from aa.browser import cf
    from aa.browser.engine import Browser

    b = Browser("tester")
    page = FakePage()
    b.pages = [page]
    b.started = True

    async def _noop(*a, **k):
        return None

    async def _inject(_b, _url):
        return 0

    async def _ensure(_b, _url):
        return {"state": "clear"}

    async def _page_state(_page):
        return {"clearance": False, "kind": None}

    monkeypatch.setattr(b, "human_wait", _noop)
    monkeypatch.setattr(cf, "inject_cached", _inject)
    monkeypatch.setattr(cf, "ensure", _ensure)
    monkeypatch.setattr(cf, "page_state", _page_state)
    return b, page


def set_mode(mode: str) -> None:
    from aa import db

    db.kv_set("mode", mode)


def set_policy(**overrides) -> None:
    from aa import config

    cfg = config.policy()
    cfg.update(overrides)
    config.save_yaml("policy.yaml", cfg)


def make_gate(payload: dict) -> dict:
    """Create a pending gate (via require, which raises Gate) and return its row.

    The approval code is captured from notify.send — the way the operator
    receives it — because since the R4 fix the code is never stored in the DB
    (hash-only). Reading g["code"] from the row would return NULL.
    """
    import re
    from unittest import mock

    from aa import db, gates

    captured = {}
    _CODE_RE = re.compile(r"aa gate approve \d+ ([A-Z0-9]{6})")

    def _capture(text, **kw):
        m = _CODE_RE.search(text)
        if m:
            captured["code"] = m.group(1)
        return False

    try:
        with mock.patch("aa.notify.send", _capture):
            gates.require("connect", "test gate", payload)
    except Gate:
        pass
    g = db.one("SELECT * FROM gates ORDER BY id DESC LIMIT 1")
    g["code"] = captured.get("code")  # delivered via notify, never stored
    return g


# ---------- R6: bad-URL navigation ----------

async def test_goto_bad_url_refused_in_safe(fake_browser):
    b, page = fake_browser
    set_mode("safe")
    with pytest.raises(Denied, match="refusing navigation"):
        await b.goto(BAD_URL)
    assert page.goto_calls == []


async def test_goto_bad_url_gated_in_balanced(fake_browser):
    b, page = fake_browser
    set_mode("balanced")
    with pytest.raises(Gate):
        await b.goto(BAD_URL)
    assert page.goto_calls == []


async def test_goto_bad_url_warns_and_continues_in_turbo(fake_browser):
    b, page = fake_browser
    set_mode("turbo")
    out = await b.goto(BAD_URL)
    assert page.goto_calls == [BAD_URL]
    assert out["scam"]["verdict"] == "bad"


@pytest.mark.parametrize("mode", ["safe", "balanced", "turbo"])
async def test_goto_blocklisted_domain_refused_every_mode(fake_browser, mode):
    b, page = fake_browser
    set_mode(mode)
    set_policy(domain_blocklist=["evil.example"])
    with pytest.raises(Denied, match="blocklisted"):
        await b.goto("https://evil.example/claim")
    # Subdomains of a listed domain are blocked too.
    with pytest.raises(Denied, match="blocklisted"):
        await b.goto("https://sub.evil.example/x")
    # The blocklist is a hard block: it applies even with check_scam=False.
    with pytest.raises(Denied, match="blocklisted"):
        await b.goto("https://evil.example/claim", check_scam=False)
    assert page.goto_calls == []


def test_check_url_blocklisted_domain(home):
    from aa import scam_check

    set_policy(domain_blocklist=["evil.example"])
    v = scam_check.check_url("https://evil.example/claim")
    assert v["verdict"] == "bad"
    assert any("blocklist" in r for r in v["reasons"])
    assert scam_check.check_url("https://sub.evil.example/")["verdict"] == "bad"
    assert scam_check.check_url("https://example.com/")["verdict"] == "ok"


# ---------- R6: drainer page text (check_page_text was dead code) ----------

async def test_goto_drainer_page_text_aborts_in_safe(fake_browser):
    b, page = fake_browser
    set_mode("safe")
    page._text = DRAINER_TEXT
    with pytest.raises(Denied, match="drainer"):
        await b.goto(CLEAN_URL)
    assert page.goto_calls == [CLEAN_URL]  # navigation happened, run aborted after


@pytest.mark.parametrize("mode", ["balanced", "turbo"])
async def test_goto_drainer_page_text_gated_outside_safe(fake_browser, mode):
    b, page = fake_browser
    set_mode(mode)
    page._text = DRAINER_TEXT
    with pytest.raises(Gate):
        await b.goto(CLEAN_URL)
    assert page.goto_calls == [CLEAN_URL]


async def test_goto_clean_page_text_proceeds_in_safe(fake_browser):
    b, page = fake_browser
    set_mode("safe")
    page._text = CLEAN_TEXT
    out = await b.goto(CLEAN_URL)
    assert page.goto_calls == [CLEAN_URL]
    assert out["text_scam"]["verdict"] == "ok"


# ---------- R7: HTTPS errors + clipboard ----------

def test_context_options_safe_forces_hardening(home):
    from aa.browser.engine import Browser

    set_mode("safe")
    # Even an explicit opt-out in policy.yaml must not weaken safe mode.
    set_policy(browser={"ignore_https_errors": True, "clipboard": True})
    opts = Browser("tester").context_options()
    assert opts == {"ignore_https_errors": False, "permissions": []}


def test_context_options_balanced_defaults(home):
    from aa.browser.engine import Browser

    set_mode("balanced")
    opts = Browser("tester").context_options()
    assert opts["ignore_https_errors"] is False
    assert opts["permissions"] == ["clipboard-read", "clipboard-write"]


def test_context_options_balanced_configurable(home):
    from aa.browser.engine import Browser

    set_mode("balanced")
    set_policy(browser={"ignore_https_errors": True, "clipboard": False})
    opts = Browser("tester").context_options()
    assert opts["ignore_https_errors"] is True
    assert opts["permissions"] == []


def test_context_options_turbo_configurable(home):
    from aa.browser.engine import Browser

    set_mode("turbo")
    set_policy(browser={"ignore_https_errors": True, "clipboard": True})
    opts = Browser("tester").context_options()
    assert opts["ignore_https_errors"] is True
    assert opts["permissions"] == ["clipboard-read", "clipboard-write"]


# ---------- R10: one approval must not mean a permanent allowlist ----------

def test_approve_safe_never_persists_domain(home):
    from aa import gates, policy

    set_mode("safe")
    g = make_gate({"_kind": "connect", "identity_id": "tester",
                   "origin": "newsite.example", "domain": "newsite.example"})
    out = gates.approve(g["id"], g["code"])
    assert out["status"] == "approved"
    assert out["domain_persisted"] is False
    assert not policy.domain_ok("newsite.example")


def test_approve_balanced_needs_explicit_opt_in(home):
    from aa import gates, policy

    set_mode("balanced")
    # No opt-in: approval is one-time only.
    g = make_gate({"_kind": "connect", "identity_id": "tester",
                   "origin": "plain.example", "domain": "plain.example"})
    out = gates.approve(g["id"], g["code"])
    assert out["domain_persisted"] is False
    assert not policy.domain_ok("plain.example")
    # Payload opt-in: persisted.
    g = make_gate({"_kind": "connect", "identity_id": "tester",
                   "origin": "optin.example", "domain": "optin.example",
                   "persist_domain": True})
    out = gates.approve(g["id"], g["code"])
    assert out["domain_persisted"] is True
    assert policy.domain_ok("optin.example")
    # Approval-time flag opt-in: persisted.
    g = make_gate({"_kind": "connect", "identity_id": "tester",
                   "origin": "flag.example", "domain": "flag.example"})
    out = gates.approve(g["id"], g["code"], persist_domain=True)
    assert out["domain_persisted"] is True
    assert policy.domain_ok("flag.example")


def test_approve_balanced_flag_ignored_in_safe(home):
    from aa import gates, policy

    set_mode("safe")
    g = make_gate({"_kind": "connect", "identity_id": "tester",
                   "origin": "flag2.example", "domain": "flag2.example"})
    out = gates.approve(g["id"], g["code"], persist_domain=True)
    assert out["domain_persisted"] is False
    assert not policy.domain_ok("flag2.example")


def test_approve_turbo_persists_domain(home):
    from aa import gates, policy

    set_mode("turbo")
    g = make_gate({"_kind": "connect", "identity_id": "tester",
                   "origin": "turbo.example", "domain": "turbo.example"})
    out = gates.approve(g["id"], g["code"])
    assert out["domain_persisted"] is True
    assert policy.domain_ok("turbo.example")


def test_connect_gate_consume_no_persist_in_safe(home):
    """The bridge consume path (the live R10 path for wallet connect)."""
    from aa import gates, policy
    from aa.browser.guards import WalletBridge

    set_mode("safe")
    bridge = WalletBridge(SimpleNamespace(identity_id="tester", chain="sepolia"))
    payload = {"_kind": "connect", "identity_id": "tester",
               "origin": "dapp.example", "domain": "dapp.example"}
    g = make_gate(payload)
    gates.approve(g["id"], g["code"])
    # Consuming the approval lets this one connect through...
    assert bridge._needs_connect_gate("dapp.example", {"verdict": "ok", "reasons": []}) is False
    # ...but must NOT leave the domain on the permanent allowlist.
    assert not policy.domain_ok("dapp.example")


def test_connect_gate_consume_persists_only_with_opt_in_balanced(home):
    from aa import gates, policy
    from aa.browser.guards import WalletBridge

    set_mode("balanced")
    bridge = WalletBridge(SimpleNamespace(identity_id="tester", chain="sepolia"))
    payload = {"_kind": "connect", "identity_id": "tester",
               "origin": "optin2.example", "domain": "optin2.example",
               "persist_domain": True}
    g = make_gate(payload)
    gates.approve(g["id"], g["code"])
    assert bridge._needs_connect_gate("optin2.example", {"verdict": "ok", "reasons": []}) is False
    assert policy.domain_ok("optin2.example")


def test_turbo_auto_allowlist_kept(home):
    from aa import policy
    from aa.browser.guards import WalletBridge

    set_mode("turbo")
    bridge = WalletBridge(SimpleNamespace(identity_id="tester", chain="sepolia"))
    assert bridge._needs_connect_gate("fresh.example", {"verdict": "ok", "reasons": []}) is False
    assert policy.domain_ok("fresh.example")
