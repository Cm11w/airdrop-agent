"""Wallet bridge between the injected page provider and the Python guards.

Every request hits policy first. The page never gets a signature the operator did not
approve (or that the active mode did not authorise within caps).
"""
from __future__ import annotations

import asyncio
import base64
import json
from urllib.parse import urlparse

from .. import chains, db, gates, policy, scam_check, vault
from ..jsonio import Denied, Gate
from ..log import get_logger
from ..wallet import send as sender
from ..wallet import sign as signer

log = get_logger("bridge")

# ---------- Solana transaction summary (R3) ----------
LAMPORTS_PER_SOL = 1_000_000_000
_SOL_SYSTEM_PROGRAM = "11111111111111111111111111111111"
_SOL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
_SOL_TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
_SOL_ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
_SOL_MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

_SOL_PROGRAM_NAMES = {
    _SOL_SYSTEM_PROGRAM: "System Program",
    _SOL_TOKEN_PROGRAM: "Token Program",
    _SOL_TOKEN_2022_PROGRAM: "Token-2022 Program",
    _SOL_ATA_PROGRAM: "Associated Token Program",
    _SOL_MEMO_PROGRAM: "Memo Program",
}


def _sol_u64(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 8], "little")


def summarize_sol_tx(tx, our_address: str) -> dict:
    """Decode a Solana transaction into a human-readable gate summary.

    Returns {"lines", "lamports_out", "recipients", "fee_payer"} where `lines`
    describes every instruction (program + decoded amounts/recipients where
    known, raw data otherwise), `lamports_out` is the lamports leaving our
    address via decoded System Program instructions, and `recipients` lists
    the distinct destination accounts. Instructions outside the decoded set
    are still listed, so the approver sees them — only their lamports are not
    counted (token value needs a price feed and is shown as raw units).
    """
    msg = tx.message
    keys = [str(k) for k in msg.account_keys]
    lines: list[str] = []
    lamports_out = 0
    recipients: list[str] = []

    def _acct(idx: int) -> str:
        return keys[idx] if 0 <= idx < len(keys) else f"#{idx}"

    for n, ix in enumerate(msg.instructions, 1):
        prog = keys[ix.program_id_index] if 0 <= ix.program_id_index < len(keys) else "?"
        name = _SOL_PROGRAM_NAMES.get(prog, f"Program {prog}")
        data = bytes(ix.data or b"")
        accts = [_acct(i) for i in (ix.accounts or [])]
        desc = None
        if prog == _SOL_SYSTEM_PROGRAM and len(data) >= 4:
            kind = int.from_bytes(data[:4], "little")
            if kind == 2 and len(data) >= 12 and len(accts) >= 2:  # Transfer
                lam = _sol_u64(data, 4)
                desc = (f"transfer {lam:,} lamports ({lam / LAMPORTS_PER_SOL:.9f} SOL) "
                        f"{accts[0]} -> {accts[1]}")
                if accts[0] == our_address:
                    lamports_out += lam
                    if accts[1] not in recipients:
                        recipients.append(accts[1])
            elif kind == 0 and len(data) >= 12 and len(accts) >= 2:  # CreateAccount
                lam = _sol_u64(data, 4)
                desc = (f"create account {accts[1]} funded with {lam:,} lamports "
                        f"({lam / LAMPORTS_PER_SOL:.9f} SOL) from {accts[0]}")
                if accts[0] == our_address:
                    lamports_out += lam
                    if accts[1] not in recipients:
                        recipients.append(accts[1])
            else:
                desc = f"system instruction {kind} (data {data.hex()[:64]})"
        elif prog in (_SOL_TOKEN_PROGRAM, _SOL_TOKEN_2022_PROGRAM) and data:
            kind = data[0]
            if kind == 3 and len(data) >= 9 and len(accts) >= 2:  # Transfer
                amount = _sol_u64(data, 1)
                desc = (f"token transfer {amount:,} (raw units) {accts[0]} -> {accts[1]} "
                        f"(authority {accts[2] if len(accts) > 2 else '?'})")
                if accts[1] not in recipients:
                    recipients.append(accts[1])
            elif kind == 12 and len(data) >= 10 and len(accts) >= 3:  # TransferChecked
                amount = _sol_u64(data, 1)
                desc = (f"token transferChecked {amount:,} (raw units, {data[9]} decimals) "
                        f"{accts[0]} -> {accts[2]} (mint {accts[1]})")
                if accts[2] not in recipients:
                    recipients.append(accts[2])
            else:
                desc = f"token instruction {kind} (data {data.hex()[:64]})"
        elif prog == _SOL_MEMO_PROGRAM:
            try:
                desc = f"memo: {data.decode('utf-8')[:120]!r}"
            except UnicodeDecodeError:
                desc = f"memo (non-utf8, {len(data)} bytes)"
        if desc is None:
            desc = f"instruction (data {data.hex()[:64] or 'empty'})"
        lines.append(f"  {n}. {name}: {desc}")
    return {"lines": lines, "lamports_out": lamports_out, "recipients": recipients,
            "fee_payer": keys[0] if keys else ""}


class WalletBridge:
    def __init__(self, browser):
        self.b = browser
        self.identity_id = browser.identity_id
        self.chain = browser.chain
        self._label = None
        self._events: list[dict] = []

    @property
    def label(self) -> str:
        if self._label:
            return self._label
        ws = db.wallets(self.identity_id, "evm")
        if not ws:
            raise Denied("identity has no EVM wallet")
        self._label = ws[0]["label"]
        return self._label

    @label.setter
    def label(self, v: str) -> None:
        self._label = v

    @property
    def address(self) -> str:
        return vault.get_address("evm", self.label)

    @property
    def sol_address(self) -> str:
        ws = db.wallets(self.identity_id, "sol")
        return ws[0]["address"] if ws else ""

    def _origin(self, source) -> str:
        """`source` comes from Playwright: a mapping whose "frame" is a Frame object."""
        try:
            frame = source.get("frame") if hasattr(source, "get") else getattr(source, "frame", None)
            url = getattr(frame, "url", None) or (frame.get("url") if hasattr(frame, "get") else "")
            return (urlparse(url or "").hostname or "").lower()
        except Exception:  # noqa: BLE001
            return ""

    def _log(self, **kw) -> None:
        kw["ts"] = db.now()
        self._events = (self._events + [kw])[-40:]

    async def events(self) -> list[dict]:
        return self._events

    # ---------- EVM ----------
    async def evm(self, source: dict, method: str, params_json: str) -> str:
        params = json.loads(params_json or "[]")
        origin = self._origin(source)
        try:
            res = await asyncio.to_thread(self._evm_sync, origin, method, params)
        except Gate as e:
            res = {"error": {"code": 4001, "message": f"approval needed: {e}"}}
        except Denied as e:
            res = {"error": {"code": 4100, "message": str(e)}}
        except Exception as e:  # noqa: BLE001
            log.exception("bridge error %s", method)
            res = {"error": {"code": -32603, "message": f"{type(e).__name__}: {e}"}}
        self._log(method=method, origin=origin, result="ok" if "error" not in res else res["error"]["message"])
        return json.dumps(res, default=str)

    def _guard(self, origin: str) -> dict:
        if not origin:
            raise Denied("no page origin")
        v = scam_check.check_url("https://" + origin)
        if v["verdict"] == "bad":
            raise Denied(f"origin {origin} looks like a drainer ({'; '.join(v['reasons'])})")
        return v

    def _needs_connect_gate(self, origin: str, verdict: dict) -> bool:
        if policy.domain_ok(origin) and verdict["verdict"] == "ok":
            return False
        if verdict["verdict"] == "ok" and policy.mode() == "turbo" and policy.cfg().get("auto_allowlist_domains", True):
            # Turbo auto-allowlist is a feature, kept — but it must be visible.
            policy.allow_domain(origin)
            log.info("turbo auto-allowlisted %s (scam_check ok) — permanent until `aa allow rm`", origin)
            db.event("policy", f"auto-allowlisted {origin}", self.identity_id)
            return False
        # NOTE: this payload must stay identical to the one gates.require()
        # stores for the connect gate (same keys, same values) or consume()
        # will never find the approval. "domain" mirrors "origin" so that
        # approving the gate via `aa gate approve` is subject to the same
        # persistence rule as the consume path below.
        payload = {"_kind": "connect", "identity_id": self.identity_id, "origin": origin,
                   "domain": origin}
        if gates.consume(payload):
            # The operator approved this connect once. That approval must NOT
            # silently become a permanent allowlist entry: safe never persists,
            # balanced only with an explicit persist_domain opt-in, turbo keeps
            # the auto-allowlist behaviour (logged above / here).
            if policy.persist_domain_allowed(payload):
                policy.allow_domain(origin)
                log.info("connect gate for %s consumed: domain persisted to the "
                         "allowlist (mode=%s)", origin, policy.mode())
            else:
                log.info("connect gate for %s consumed: one-time approval only, "
                         "domain NOT added to the allowlist (mode=%s)",
                         origin, policy.mode())
            return False
        return True

    def _evm_sync(self, origin: str, method: str, params: list) -> dict:
        if method == "eth_accounts":
            return {"result": [self.address]}
        if method in ("eth_chainId", "net_version"):
            cid = int(chains.cfg(self.chain)["chain_id"])
            return {"result": hex(cid) if method == "eth_chainId" else str(cid)}
        if method == "wallet_getPermissions":
            return {"result": [{"parentCapability": "eth_accounts"}]}
        if method in ("wallet_requestPermissions", "eth_requestAccounts"):
            v = self._guard(origin)
            if self._needs_connect_gate(origin, v):
                gates.require("connect", f"Connect wallet {self.address} ke {origin} "
                                         f"(scam_check={v['verdict']}: {'; '.join(v['reasons']) or 'clean'})",
                              {"_kind": "connect", "identity_id": self.identity_id, "origin": origin,
                               "domain": origin})
            return {"result": [self.address]}
        if method == "wallet_switchEthereumChain":
            want = int(params[0]["chainId"], 16) if params else 0
            for name in chains.all_chains():
                if int(policy.chain(name)["chain_id"]) == want:
                    self.chain = name
                    self.b.chain = name
                    return {"result": None, "chainId": hex(want)}
            raise Denied(f"chain {want} not in policy.yaml")
        if method == "wallet_watchAsset":
            return {"result": True}
        if method == "personal_sign":
            msg = params[0]
            text = _decode_hex(msg)
            out = signer.personal(self.identity_id, self.label, text, origin, broadcast_gate=True)
            self._log(kind="sign_text", origin=origin)
            return {"result": out["signature"]}
        if method in ("eth_signTypedData_v4", "eth_signTypedData_v3", "eth_signTypedData"):
            typed = params[1] if len(params) > 1 else params[0]
            out = signer.typed(self.identity_id, self.label, typed, origin)
            self._log(kind="sign_typed", origin=origin)
            return {"result": out["signature"]}
        if method == "eth_sendTransaction":
            tx = params[0]
            to = tx.get("to")
            if not to:
                raise Denied("contract creation from the page is not supported yet")
            value = int(tx.get("value", "0x0"), 16)
            data = tx.get("data") or tx.get("input") or "0x"
            out = sender.send(self.chain, self.identity_id, self.label, to,
                              value_wei=value, calldata=data, broadcast=True, via="browser")
            return {"result": out["tx"], "proof": out.get("proof")}
        if method == "eth_estimateGas":
            w3, _ = chains.w3(self.chain)
            tx = params[0]
            gas = w3.eth.estimate_gas({"from": tx.get("from", self.address), "to": tx.get("to"),
                                       "value": int(tx.get("value", "0x0"), 16),
                                       "data": tx.get("data", "0x")})
            return {"result": hex(gas)}
        if method in ("eth_gasPrice", "eth_blockNumber", "eth_getBalance", "eth_getTransactionCount",
                      "eth_getTransactionReceipt", "eth_call"):
            w3, _ = chains.w3(self.chain)
            if method == "eth_call":
                p = params[0]
                r = w3.eth.call({"to": p.get("to"), "data": p.get("data", "0x")},
                                p.get("block_identifier", "latest"))
                return {"result": r.hex()}
            if method == "eth_gasPrice":
                return {"result": hex(w3.eth.gas_price)}
            if method == "eth_blockNumber":
                return {"result": hex(w3.eth.block_number)}
            if method == "eth_getBalance":
                return {"result": hex(w3.eth.get_balance(params[0]))}
            if method == "eth_getTransactionCount":
                return {"result": hex(w3.eth.get_transaction_count(params[0]))}
            if method == "eth_getTransactionReceipt":
                r = w3.eth.get_transaction_receipt(params[0])
                return {"result": dict(r) if r else None}
            return {"result": None}
        raise Denied(f"unsupported method {method}")

    # ---------- Solana ----------
    async def solana(self, source: dict, method: str, params_json: str) -> str:
        params = json.loads(params_json or "[]")
        origin = self._origin(source)
        try:
            res = await asyncio.to_thread(self._sol_sync, origin, method, params)
        except Gate as e:
            res = {"error": {"code": 4001, "message": f"approval needed: {e}"}}
        except Denied as e:
            res = {"error": {"code": 4100, "message": str(e)}}
        except Exception as e:  # noqa: BLE001
            log.exception("sol bridge error %s", method)
            res = {"error": {"code": -32603, "message": f"{type(e).__name__}: {e}"}}
        self._log(method=f"sol:{method}", origin=origin)
        return json.dumps(res, default=str)

    def _sol_addr(self) -> str:
        ws = db.wallets(self.identity_id, "sol")
        if not ws:
            raise Denied("identity has no Solana wallet")
        return ws[0]["address"]

    def _sol_sync(self, origin: str, method: str, params: list) -> dict:
        from solders.transaction import Transaction

        v = self._guard(origin)
        if method in ("connect", "wallet_requestPermissions", "eth_requestAccounts"):
            if self._needs_connect_gate(origin, v):
                gates.require("connect", f"Connect Solana wallet {self._sol_addr()} ke {origin} "
                                         f"(scam_check={v['verdict']})",
                              {"_kind": "connect", "identity_id": self.identity_id, "origin": origin,
                               "chain_family": "sol", "domain": origin})
            return {"result": {"publicKey": self._sol_addr()}}
        if method in ("disconnect",):
            return {"result": None}
        if method == "signMessage":
            # R2: same bar as EVM personal_sign — origin must be allowlisted and
            # the signature gates per policy (safe mode always gates). A page
            # that is not allowlisted gets a Denied, never a signature.
            signer._check_origin(origin)
            raw = params[0]
            data = bytes(raw) if isinstance(raw, list) else base64.b64decode(raw)
            ws = db.wallets(self.identity_id, "sol")
            text = data.decode("utf-8", "replace")
            payload = {"_kind": "sign_text", "identity_id": self.identity_id,
                       "label": ws[0]["label"], "message": text, "origin": origin,
                       "chain_family": "sol"}
            gate, _reasons = policy.needs_gate("sign_text", identity_id=self.identity_id)
            if gate and not gates.consume(payload):
                gates.require("sign_text",
                              f"Sign Solana message di {origin} ({len(data)} bytes)\n{text[:280]}",
                              payload)
            kp = vault.load_sol(ws[0]["label"])
            sig = kp.sign_message(data)
            self._log(kind="sign_text_sol", origin=origin)
            return {"result": {"signature": list(bytes(sig)), "publicKey": self._sol_addr()}}
        if method in ("signTransaction", "signAndSendTransaction"):
            cfg = chains.sol("solana-devnet" if "solana-devnet" in chains.all_chains() else
                             [c for c in chains.all_chains() if policy.chain(c).get("kind") == "solana"][0])
            raw = params[0]
            tx_bytes = base64.b64decode(raw) if isinstance(raw, str) else bytes(raw)
            tx = Transaction.from_bytes(tx_bytes)
            ws = db.wallets(self.identity_id, "sol")
            kp = vault.load_sol(ws[0]["label"])
            from ..wallet import sol as solw

            sim = solw.rpc(cfg, "simulateTransaction", [base64.b64encode(tx_bytes).decode(),
                                                       {"sigVerify": False, "replaceRecentBlockhash": True}])
            if (sim or {}).get("value", {}).get("err"):
                raise Denied(f"solana simulation failed: {sim['value']['err']}")
            # R3: summarise the real transaction — lamports, recipients,
            # instructions — and cap-check the actual outgoing value, not the
            # wallet balance (the old code always passed value 5000 / balance).
            summary = summarize_sol_tx(tx, self._sol_addr())
            value_est = summary["lamports_out"]
            policy.check_value(cfg["name"], ws[0]["label"], value_est, 5000, 1)
            payload = {"_kind": "tx", "chain": cfg["name"], "identity": self.identity_id,
                       "label": ws[0]["label"], "to": "solana-tx", "value": str(value_est),
                       "data": base64.b64encode(tx_bytes).decode()[:4000]}
            if not gates.consume(payload):
                detail = (f"Solana transaction dari {self._sol_addr()} "
                          f"({'signAndSend' if method == 'signAndSendTransaction' else 'sign'}) "
                          f"(fee payer {summary['fee_payer']})\n"
                          f"Instruksi ({len(summary['lines'])}):\n" + "\n".join(summary["lines"]) +
                          f"\nTotal lamports keluar: {value_est:,} "
                          f"({value_est / LAMPORTS_PER_SOL:.9f} SOL)")
                if summary["recipients"]:
                    detail += f"\nPenerima: {', '.join(summary['recipients'])}"
                if any("token transfer" in ln for ln in summary["lines"]):
                    detail += ("\nCatatan: nilai token tidak dihitung (butuh harga); "
                               "jumlah raw units ada di atas.")
                gates.require("tx", detail, payload)
            tx.sign([kp], tx.message.recent_blockhash)
            signed = base64.b64encode(bytes(tx)).decode()
            if method == "signTransaction":
                return {"result": signed}
            sig = solw.rpc(cfg, "sendTransaction", [signed, {"encoding": "base64", "skipPreflight": False}])
            db.add_spend(cfg["name"], ws[0]["label"], value_est + 5000)
            db.event("tx", f"sol {sig}", self.identity_id, data={"chain": cfg["name"]})
            return {"result": sig}
        raise Denied(f"unsupported solana method {method}")


_SNAKE = {
    "eth_gasPrice": "gas_price", "eth_blockNumber": "block_number", "eth_getBalance": "get_balance",
    "eth_getTransactionCount": "get_transaction_count", "eth_getTransactionReceipt": "get_transaction_receipt",
}


def _decode_hex(msg) -> str:
    if isinstance(msg, str) and msg.startswith("0x"):
        try:
            return bytes.fromhex(msg[2:]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return msg
    return str(msg)
