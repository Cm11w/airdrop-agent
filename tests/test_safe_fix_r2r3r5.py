"""Safe-mode fixes R2/R3/R5.

R2  Solana signMessage in the browser bridge had no origin allowlist and no
    gate — mirror EVM personal_sign (allowlist + policy gate).
R3  The Solana tx gate was blind: the summary showed no amount/recipient and
    the value check used the wallet balance (always 5000) instead of the tx.
R5  SIWE domain check in personal() was documented but never enforced:
    a message whose domain differs from the page origin must be Denied in
    every mode.
"""
import base64

import pytest
from types import SimpleNamespace

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

from aa import db, policy
from aa.browser import guards as bridge_guards
from aa.jsonio import Denied, Gate
from aa.wallet import sign as signer

ALLOWED_ORIGIN = "galxe.com"  # in config/policy.yaml domain_allowlist
DENIED_ORIGIN = "notallowed.example.com"  # passes scam check, not allowlisted
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


def _bridge(identity_id):
    fake = SimpleNamespace(identity_id=identity_id, chain="solana-devnet")
    return bridge_guards.WalletBridge(fake)


def _sol_wallet(identity_id):
    ws = db.wallets(identity_id, "sol")
    assert ws, "ident fixture must derive a sol wallet"
    return ws[0]


def _evm_label(identity_id):
    ws = db.wallets(identity_id, "evm")
    assert ws, "ident fixture must derive an evm wallet"
    return ws[0]["label"]


def _make_transfer_tx(from_addr, to_addr, lamports, extra_ix=None):
    ixs = [transfer(TransferParams(from_pubkey=Pubkey.from_string(from_addr),
                                   to_pubkey=Pubkey.from_string(to_addr),
                                   lamports=lamports))]
    if extra_ix is not None:
        ixs.append(extra_ix)
    msg = Message.new_with_blockhash(ixs, Pubkey.from_string(from_addr), Hash.default())
    return Transaction.new_unsigned(msg)


def _token_transfer_ix(amount):
    src = Keypair().pubkey()
    dst = Keypair().pubkey()
    data = bytes([3]) + int(amount).to_bytes(8, "little")
    ix = Instruction(Pubkey.from_string(TOKEN_PROGRAM), data,
                     [AccountMeta(src, False, True), AccountMeta(dst, False, False),
                      AccountMeta(src, True, False)])
    return ix, str(dst)


def _siwe_message(domain):
    return (f"{domain} wants you to sign in with your Ethereum account:\n"
            f"0x0000000000000000000000000000000000000001\n\n"
            f"URI: https://{domain}\n"
            f"Version: 1\nChain ID: 1\nNonce: abc123\n"
            f"Issued At: 2026-11-19T00:00:00Z")


def _fake_sol_rpc(monkeypatch, send_sig="FAKESIG123"):
    from aa.wallet import sol as solw

    def _rpc(cfg, method, params):
        if method == "simulateTransaction":
            return {"value": {"err": None}}
        if method == "sendTransaction":
            return send_sig
        raise AssertionError(f"unexpected sol rpc call {method}")

    monkeypatch.setattr(solw, "rpc", _rpc)


# ---------- R2: Solana signMessage ----------

def test_r2_sign_message_non_allowlisted_origin_denied(home, ident):
    b = _bridge(ident)
    with pytest.raises(Denied, match="not in the domain allowlist"):
        b._sol_sync(DENIED_ORIGIN, "signMessage", [list(b"hello")])


def test_r2_sign_message_safe_mode_requires_gate(home, ident):
    policy.set_mode("safe")
    b = _bridge(ident)
    with pytest.raises(Gate, match="approval .* required"):
        b._sol_sync(ALLOWED_ORIGIN, "signMessage", [list(b"hello")])


def test_r2_sign_message_balanced_allowlisted_signs(home, ident):
    b = _bridge(ident)
    out = b._sol_sync(ALLOWED_ORIGIN, "signMessage", [list(b"hello")])
    assert len(out["result"]["signature"]) == 64
    assert out["result"]["publicKey"] == _sol_wallet(ident)["address"]


# ---------- R3: Solana tx summary + real value ----------

def test_r3_summary_shows_lamports_recipient_instructions(home, ident):
    from_addr = _sol_wallet(ident)["address"]
    to_addr = str(Keypair().pubkey())
    token_ix, token_dst = _token_transfer_ix(250)
    tx = _make_transfer_tx(from_addr, to_addr, 1_500_000, extra_ix=token_ix)
    s = bridge_guards.summarize_sol_tx(tx, from_addr)
    assert s["lamports_out"] == 1_500_000
    assert to_addr in s["recipients"] and token_dst in s["recipients"]
    joined = "\n".join(s["lines"])
    assert "1,500,000 lamports" in joined
    assert "0.001500000 SOL" in joined
    assert to_addr in joined
    assert "Token Program: token transfer 250" in joined
    assert s["fee_payer"] == from_addr


def test_r3_gate_summary_contains_amount_and_recipient(home, ident, monkeypatch):
    _fake_sol_rpc(monkeypatch)
    from_addr = _sol_wallet(ident)["address"]
    to_addr = str(Keypair().pubkey())
    tx = _make_transfer_tx(from_addr, to_addr, 1_500_000)
    b = _bridge(ident)
    with pytest.raises(Gate) as exc:
        b._sol_sync(ALLOWED_ORIGIN, "signTransaction",
                    [base64.b64encode(bytes(tx)).decode()])
    msg = str(exc.value)
    assert "1,500,000 lamports" in msg
    assert "0.001500000 SOL" in msg
    assert to_addr in msg
    assert "Total lamports keluar" in msg


def test_r3_tx_over_per_tx_cap_denied(home, ident, monkeypatch):
    """1 SOL > 0.2 SOL devnet per-tx cap: the old code passed value 5000 and
    would have let this through to the gate."""
    _fake_sol_rpc(monkeypatch)
    from_addr = _sol_wallet(ident)["address"]
    tx = _make_transfer_tx(from_addr, str(Keypair().pubkey()), 1_000_000_000)
    b = _bridge(ident)
    with pytest.raises(Denied, match="per-tx cap"):
        b._sol_sync(ALLOWED_ORIGIN, "signTransaction",
                    [base64.b64encode(bytes(tx)).decode()])


def test_r3_sign_and_send_records_real_spend(home, ident, monkeypatch):
    from aa import gates
    from aa.wallet import sol as solw  # noqa: F401  (imported for clarity)

    _fake_sol_rpc(monkeypatch)
    monkeypatch.setattr(gates, "consume", lambda payload: {"gate": 1})
    from_addr = _sol_wallet(ident)["address"]
    label = _sol_wallet(ident)["label"]
    tx = _make_transfer_tx(from_addr, str(Keypair().pubkey()), 1_500_000)
    b = _bridge(ident)
    out = b._sol_sync(ALLOWED_ORIGIN, "signAndSendTransaction",
                      [base64.b64encode(bytes(tx)).decode()])
    assert out["result"] == "FAKESIG123"
    # spend recorded = lamports out + 5000 fee (old code recorded the balance)
    assert db.spent_today("solana-devnet", label) == 1_500_000 + 5000


# ---------- R5: SIWE domain check ----------

@pytest.mark.parametrize("mode", ["safe", "balanced", "turbo"])
def test_r5_siwe_domain_mismatch_denied_in_all_modes(home, ident, mode):
    policy.set_mode(mode)
    label = _evm_label(ident)
    with pytest.raises(Denied, match="SIWE domain mismatch"):
        signer.personal(ident, label, _siwe_message("evil.com"), ALLOWED_ORIGIN)


def test_r5_siwe_domain_match_signs(home, ident):
    label = _evm_label(ident)
    out = signer.personal(ident, label, _siwe_message("galxe.com"), ALLOWED_ORIGIN)
    assert out["signature"].startswith("0x")
    assert out["summary"]["domain_field"] == "galxe.com"


def test_r5_no_domain_field_still_requires_allowlisted_origin(home, ident):
    label = _evm_label(ident)
    with pytest.raises(Denied, match="not in the domain allowlist"):
        signer.personal(ident, label, "just a plain message", DENIED_ORIGIN)
    out = signer.personal(ident, label, "just a plain message", ALLOWED_ORIGIN)
    assert out["signature"].startswith("0x")
