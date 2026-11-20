"""Safe-mode fixes: R1/R9 (branch safe-fix-a) + R8/R11/R12/R13 (branch safe-fix-d).

R1  unlimited approval always gates, in every mode; approve() needs an
    explicit amount (unlimited only via unlimited=True / --unlimited).
R9  sol.send() gates like EVM send().
R8  seed_rabby writes an encrypted vault-style blob, never plaintext.
R11 quest eval/api steps need an explicit opt-in and are refused in safe mode;
    faucet claim() forces check_scam=True in safe mode.
R12 radar auto-queue is off in safe mode; autopilot follow/quests need an
    explicit safe_allow_* opt-in in autopilot.yaml while in safe mode.
R13 Discord self-bot is disabled in safe mode and needs an explicit
    social.discord_selfbot opt-in otherwise; external grind LLM is off in
    safe mode (local fallback only).

No network: the EVM chain and the Solana RPC are faked in-process.
"""
import asyncio
import stat

import pytest
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_utils import to_checksum_address

from aa.jsonio import Denied, Gate


MAX = 2 ** 256 - 1
TOKEN = to_checksum_address("0x" + "11" * 20)
SPENDER = to_checksum_address("0x" + "22" * 20)


def approve_calldata(spender: str, amount: int) -> str:
    return "0x095ea7b3" + abi_encode(["address", "uint256"], [spender, amount]).hex()


# ---------- fake EVM chain ----------

class _FakeEth:
    def estimate_gas(self, tx):
        return 50000

    def get_block(self, name):
        return {"baseFeePerGas": 10 ** 9}

    @property
    def gas_price(self):
        return 10 ** 9

    @property
    def max_priority_fee(self):
        return 10 ** 9

    def get_transaction_count(self, addr):
        return 0


class _FakeW3:
    def __init__(self):
        self.eth = _FakeEth()

    def to_wei(self, v, unit):
        return int(v * 10 ** 9) if unit == "gwei" else int(v)


@pytest.fixture
def fake_evm(monkeypatch):
    from aa.wallet import send as sender

    monkeypatch.setattr(sender.chains, "w3",
                        lambda chain: (_FakeW3(), {"chain_id": 11155111, "testnet": True}))
    monkeypatch.setattr(sender.vault, "load_evm", lambda label: Account.create())
    return sender


@pytest.fixture
def allowlisted_token(home):
    """Allowlist the token contract, so the ONLY thing that can still force a
    gate is the unlimited-approval rule itself."""
    from aa import config

    y = config.policy()
    y.setdefault("contracts_allowlist", {})["sepolia"] = [TOKEN]
    config.save_yaml("policy.yaml", y)


# ---------- R1: unlimited approval always gates ----------

@pytest.mark.parametrize("mode", ["balanced", "turbo"])
def test_unlimited_approval_always_gates(home, fake_evm, allowlisted_token, mode):
    from aa import policy
    from aa.wallet import send as sender

    policy.set_mode(mode)
    with pytest.raises(Gate):
        sender.send("sepolia", "id-x", "label", TOKEN,
                    calldata=approve_calldata(SPENDER, MAX), broadcast=False)


def test_set_approval_for_all_true_always_gates(home, fake_evm, allowlisted_token):
    """setApprovalForAll(true) is the NFT equivalent of an unlimited approval
    (integration addition) — it must gate even when the contract is allowlisted."""
    from aa import policy
    from aa.wallet import send as sender

    policy.set_mode("balanced")
    calldata = "0xa22cb465" + abi_encode(["address", "bool"], [SPENDER, True]).hex()
    with pytest.raises(Gate):
        sender.send("sepolia", "id-x", "label", TOKEN,
                    calldata=calldata, broadcast=False)


def test_set_approval_for_all_false_stays_auto(home, fake_evm, allowlisted_token):
    """Revoking an approval (false) is not an unlimited grant — stays automatic."""
    from aa import policy
    from aa.wallet import send as sender

    policy.set_mode("balanced")
    calldata = "0xa22cb465" + abi_encode(["address", "bool"], [SPENDER, False]).hex()
    sender.send("sepolia", "id-x", "label", TOKEN,
                calldata=calldata, broadcast=False)


@pytest.mark.parametrize("mode", ["balanced", "turbo"])
def test_limited_approval_still_auto(home, fake_evm, allowlisted_token, mode):
    from aa import policy
    from aa.wallet import send as sender

    policy.set_mode(mode)
    out = sender.send("sepolia", "id-x", "label", TOKEN,
                      calldata=approve_calldata(SPENDER, 1000), broadcast=False)
    assert out["simulated"] is True


def test_approve_requires_explicit_amount(home):
    from aa.wallet import send as sender

    with pytest.raises(Denied, match="explicit amount"):
        sender.approve("sepolia", "id-x", "label", TOKEN, SPENDER)


def test_approve_unlimited_flag_builds_max(home, monkeypatch):
    from aa.wallet import send as sender

    seen = {}
    monkeypatch.setattr(sender, "send", lambda *a, **kw: seen.setdefault("calldata", kw.get("calldata")))
    sender.approve("sepolia", "id-x", "label", TOKEN, SPENDER, unlimited=True)
    from aa.wallet.send import decode

    dec = decode(seen["calldata"])
    assert dec["kind"] == "approve" and int(dec["amount"]) == MAX


def test_approve_explicit_amount_kept(home, monkeypatch):
    from aa.wallet import send as sender
    from aa.wallet.send import decode

    seen = {}
    monkeypatch.setattr(sender, "send", lambda *a, **kw: seen.setdefault("calldata", kw.get("calldata")))
    sender.approve("sepolia", "id-x", "label", TOKEN, SPENDER, amount=1234)
    assert int(decode(seen["calldata"])["amount"]) == 1234


# ---------- R9: sol.send gates inside the library ----------

@pytest.fixture
def fake_sol_rpc(monkeypatch):
    from aa.wallet import sol as solw

    def _rpc(cfg, method, params):
        if method == "getLatestBlockhash":
            return {"value": {"blockhash": "11111111111111111111111111111111"}}
        if method == "simulateTransaction":
            return {"value": {"err": None, "unitsConsumed": 1000}}
        raise AssertionError(f"unexpected RPC call: {method}")

    monkeypatch.setattr(solw, "rpc", _rpc)
    return solw


def _sol_wallet(ident):
    from aa import db

    return db.wallets(ident, "sol")[0]


def _to_pubkey():
    from solders.keypair import Keypair

    return str(Keypair().pubkey())


def test_sol_send_gates_on_mainnet(home, ident, fake_sol_rpc):
    from aa import policy
    from aa.wallet import sol as solw

    policy.set_mode("balanced")
    w = _sol_wallet(ident)
    cfg = {"name": "solana", "rpc": "https://example.invalid", "testnet": False}
    with pytest.raises(Gate):
        solw.send(cfg, w["label"], _to_pubkey(), 1_000_000, identity_id=ident)


def test_sol_send_gates_in_safe_mode(home, ident, fake_sol_rpc):
    from aa import policy
    from aa.wallet import sol as solw

    policy.set_mode("safe")
    w = _sol_wallet(ident)
    cfg = {"name": "solana-devnet", "rpc": "https://example.invalid", "testnet": True}
    with pytest.raises(Gate):
        solw.send(cfg, w["label"], _to_pubkey(), 1_000_000, identity_id=ident)


def test_sol_send_auto_on_testnet(home, ident, fake_sol_rpc):
    from aa import policy
    from aa.wallet import sol as solw

    policy.set_mode("balanced")
    w = _sol_wallet(ident)
    cfg = {"name": "solana-devnet", "rpc": "https://example.invalid", "testnet": True}
    out = solw.send(cfg, w["label"], _to_pubkey(), 1_000_000, identity_id=ident)
    assert out["simulated"] is True


def test_sol_send_proceeds_after_approval(home, ident, fake_sol_rpc):
    from tests.test_gates import capture_code
    from unittest import mock

    from aa import gates, policy
    from aa.wallet import sol as solw

    policy.set_mode("balanced")
    w = _sol_wallet(ident)
    cfg = {"name": "solana", "rpc": "https://example.invalid", "testnet": False}
    to = _to_pubkey()
    captured, _capture = capture_code()
    with mock.patch("aa.notify.send", _capture):
        with pytest.raises(Gate):
            solw.send(cfg, w["label"], to, 1_000_000, identity_id=ident)
    gid = gates.list_gates()[0]["id"]
    gates.approve(gid, captured["code"])
    out = solw.send(cfg, w["label"], to, 1_000_000, identity_id=ident)
    assert out["simulated"] is True


# ---------------- R8 / R11 / R12 / R13 (safe-fix-d) ----------------

def _set_mode(mode: str):
    from aa import db

    db.kv_set("mode", mode)


def _quest_with(step: dict, **extra):
    from aa.quest import dsl

    q = dsl.scaffold("Safe Test", "https://example.com", "generic", "sepolia")
    q["steps"].append(step)
    q.update(extra)
    return q


# ---------------- R8 ----------------
def test_seed_rabby_is_encrypted_not_plaintext(home):
    from aa.wallet import ext

    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    p = ext.seed_rabby("ident-1", mnemonic, "s3cret-pw")
    assert p.exists()
    raw = p.read_bytes()
    assert mnemonic.encode() not in raw, "mnemonic leaked into seed file in plaintext"
    assert b"s3cret-pw" not in raw, "password leaked into seed file in plaintext"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    back = ext.load_rabby_seed("ident-1")
    assert back == {"mnemonic": mnemonic, "password": "s3cret-pw"}


def test_seed_rabby_overwrite_keeps_encryption(home):
    from aa.wallet import ext

    ext.seed_rabby("ident-1", "word " * 11 + "about", "pw1")
    ext.seed_rabby("ident-1", "zoo " * 11 + "about", "pw2")
    back = ext.load_rabby_seed("ident-1")
    assert back["password"] == "pw2"
    assert b"pw2" not in (ext.config.EXT_DIR / "ident-1" / "rabby.seed").read_bytes()


def test_load_rabby_seed_missing_raises(home):
    from aa.wallet import ext

    with pytest.raises(Denied):
        ext.load_rabby_seed("nobody")


# ---------------- R11: quest eval/api ----------------
def test_eval_without_optin_fails_validation(home):
    from aa.quest import dsl

    q = _quest_with({"eval": "document.title"})
    assert any("allow_eval" in e for e in dsl.validate(q))


def test_api_without_optin_fails_validation(home):
    from aa.quest import dsl

    q = _quest_with({"api": {"url": "https://example.com/x"}})
    assert any("allow_api" in e for e in dsl.validate(q))


def test_eval_with_optin_passes_outside_safe(home):
    from aa.quest import dsl

    q = _quest_with({"eval": "document.title"}, allow_eval=True)
    assert dsl.validate(q) == []
    q2 = _quest_with({"api": {"url": "https://example.com/x"}}, allow_api=True)
    assert dsl.validate(q2) == []


def test_eval_rejected_in_safe_mode_even_with_optin(home):
    from aa.quest import dsl

    _set_mode("safe")
    q = _quest_with({"eval": "document.title"}, allow_eval=True)
    errs = dsl.validate(q)
    assert any("safe mode" in e for e in errs)
    q2 = _quest_with({"api": {"url": "https://example.com/x"}}, allow_api=True)
    assert any("safe mode" in e for e in dsl.validate(q2))


def test_plain_quest_still_valid_in_safe_mode(home):
    from aa.quest import dsl

    _set_mode("safe")
    q = dsl.scaffold("Plain", "https://example.com", "generic", "sepolia")
    assert dsl.validate(q) == []


def test_runner_arbitrary_step_guard(home):
    from aa.quest import runner

    _set_mode("safe")
    with pytest.raises(Denied, match="safe mode"):
        runner._check_arbitrary_step({"allow_eval": True}, "eval")
    _set_mode("balanced")
    with pytest.raises(Denied, match="allow_eval"):
        runner._check_arbitrary_step({}, "eval")
    runner._check_arbitrary_step({"allow_eval": True}, "eval")  # no raise


# ---------------- R11: faucet scam check ----------------
class _GotoRecorder:
    """Minimal fake browser: records goto() kwargs, then stops the claim."""

    def __init__(self):
        self.goto_kwargs = None
        self.page = self

    def set_default_timeout(self, ms):
        pass

    async def goto(self, url, **kw):
        self.goto_kwargs = kw
        raise RuntimeError("stop-after-goto")


async def _claim_with_recorder(ident, mode):
    from aa.testnet import faucets

    _set_mode(mode)
    b = _GotoRecorder()
    with pytest.raises(RuntimeError, match="stop-after-goto"):
        await faucets.claim(b, ident, "sepolia", "sepolia-alchemy")
    return b.goto_kwargs


def test_faucet_claim_forces_scam_check_in_safe_mode(home, ident):
    kw = asyncio.run(_claim_with_recorder(ident, "safe"))
    assert kw == {"check_scam": True}


def test_faucet_claim_keeps_old_behaviour_outside_safe(home, ident):
    kw = asyncio.run(_claim_with_recorder(ident, "balanced"))
    assert kw == {"check_scam": False}


# ---------------- R12: radar auto-queue ----------------
def _radar_item():
    return {"kind": "airdrop", "source": "test", "project": "SafeProj",
            "text": "incentivized testnet with points program, whitelist mint free",
            "trust": 3, "links": [{"url": "https://app.uniswap.org/claim", "type": "web"}]}


def test_radar_autoqueue_off_in_safe_mode(home):
    from aa.radar import pipeline

    _set_mode("safe")
    res = pipeline.ingest([_radar_item()])
    assert res["stored"] == 1
    assert res["queued"] == []
    from aa import db

    assert db.one("SELECT 1 FROM quests WHERE id LIKE 'radar-%'") is None


def test_radar_autoqueue_on_outside_safe_mode(home):
    from aa.radar import pipeline

    _set_mode("balanced")
    res = pipeline.ingest([_radar_item()])
    assert res["stored"] == 1
    assert len(res["queued"]) == 1


# ---------------- R12: autopilot safe opt-in ----------------
def test_autopilot_follow_quests_blocked_in_safe_without_optin(home):
    from aa import autopilot

    _set_mode("safe")
    assert autopilot._safe_allowed("safe_allow_follow") is False
    assert autopilot._safe_allowed("safe_allow_quests") is False


def test_autopilot_safe_optin_enables_modules(home):
    from aa import autopilot, config

    _set_mode("safe")
    cfg = config.load_yaml("autopilot.yaml")
    cfg["safe_allow_follow"] = True
    cfg["safe_allow_quests"] = True
    config.save_yaml("autopilot.yaml", cfg)
    assert autopilot._safe_allowed("safe_allow_follow") is True
    assert autopilot._safe_allowed("safe_allow_quests") is True


def test_autopilot_modules_unaffected_outside_safe(home):
    from aa import autopilot

    _set_mode("balanced")
    assert autopilot._safe_allowed("safe_allow_follow") is True
    assert autopilot._safe_allowed("safe_allow_quests") is True


# ---------------- R13: Discord ----------------
def test_discord_disabled_in_safe_mode(home):
    from aa.social import discord

    _set_mode("safe")
    with pytest.raises(Denied, match="disabled in safe mode"):
        discord.token("ident-1")
    with pytest.raises(Denied, match="disabled in safe mode"):
        asyncio.run(discord.login("ident-1", "a@b.c", "pw"))


def test_discord_needs_optin_outside_safe(home):
    from aa.social import discord

    _set_mode("balanced")
    with pytest.raises(Denied, match="opt-in"):
        discord.token("ident-1")


def _set_discord_optin(value: bool):
    from aa import config, policy

    cfg = policy.cfg()
    cfg.setdefault("social", {})["discord_selfbot"] = value
    config.save_yaml("policy.yaml", cfg)


def test_discord_optin_passes_gate_then_reports_missing_token(home):
    from aa.social import discord

    _set_mode("balanced")
    _set_discord_optin(True)
    with pytest.raises(Denied, match="no Discord token"):
        discord.token("ident-1")


def test_grind_llm_disabled_in_safe_mode(home, monkeypatch):
    from aa import humanize

    _set_mode("safe")
    monkeypatch.delenv("LLM_MOCK", raising=False)
    monkeypatch.setenv("GRIND_LLM_BASE_URL", "https://llm.example.invalid/v1")
    monkeypatch.setenv("GRIND_LLM_API_KEY", "test-key")

    def _boom(*a, **kw):
        raise AssertionError("external LLM must not be called in safe mode")

    monkeypatch.setattr(humanize.requests, "post", _boom)
    assert humanize.llm_available() is False
    assert humanize.llm("hello") is None


def test_grind_llm_reachable_outside_safe_mode(home, monkeypatch):
    from aa import humanize

    _set_mode("balanced")
    monkeypatch.delenv("LLM_MOCK", raising=False)
    monkeypatch.setenv("GRIND_LLM_BASE_URL", "https://llm.example.invalid/v1")
    monkeypatch.setenv("GRIND_LLM_API_KEY", "test-key")

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"choices": [{"message": {"content": "ok reply"}}]}

    monkeypatch.setattr(humanize.requests, "post", lambda *a, **kw: _Resp())
    assert humanize.llm_available() is True
    assert humanize.llm("hello") == "ok reply"
