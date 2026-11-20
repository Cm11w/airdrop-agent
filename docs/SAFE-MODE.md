# Safe mode — airdrop-agent

Safe mode is the strictest operating mode of this fork. It exists because the
upstream documentation claimed protections the code did not enforce (see the
13 findings fixed on branch `safe-mode`). In safe mode, **everything risky
gates or is refused** — nothing runs on autopilot, nothing is auto-approved,
and no feature silently widens its own permissions.

Enable it any time:

```
aa mode safe
```

`aa mode` shows the current mode. Switching modes is itself a local
decision — there is no remote control and no server that can change it.

> **Nothing is removed.** Turbo mode, the Discord self-bot, quest `eval`/`api`
> steps, auto-follow, radar auto-queue and the clipboard all still exist.
> Safe mode only changes *when* they may run and *what approval they need*.
> Outside safe mode the fixes below still apply where they are root-cause
> fixes (marked **all modes**).

## What safe mode enforces

| # | Finding (upstream) | Safe mode | Other modes |
|---|---|---|---|
| R1 | Unlimited approval only logged, never gated | Always gates (all modes); `approve()` needs an explicit amount; `--unlimited` is explicit + warned | Same — root fix, all modes |
| R1b | `setApprovalForAll(true)` (NFT unlimited) not gated | Always gates (all modes) | Same — root fix, all modes |
| R2 | Solana `signMessage` in the bridge: no gate, no origin check | Origin must be allowlisted + gate (safe always gates) | Origin allowlist + gate per policy |
| R3 | Solana tx gate was blind (no amount/recipient; value always 0) | Gate summary lists instructions, lamports out, recipients, fee payer; `check_value` uses real lamports | Same — root fix, all modes |
| R4 | Gate codes stored in plaintext in SQLite | Codes stored as salted SHA-256 hash only; old plaintext nulled by migration; DB file 0600 | Same — root fix, all modes |
| R5 | SIWE domain check not enforced | Domain in the signed message must match the page origin (all modes) | Same — root fix, all modes |
| R6 | Navigation to a "bad" domain only warned and continued; drainer-text detection was dead code | Navigation **refused**; drainer text on the page aborts the run | Balanced: gate/confirmation required. Turbo: warning (old behaviour) |
| R7 | `ignore_https_errors: true` + clipboard permissions | HTTPS errors enforced, no clipboard permissions | Configurable via `browser:` in `policy.yaml` (default `ignore_https_errors: false`) |
| R8 | `seed_rabby` wrote the mnemonic in plaintext | Encrypted vault-style blob (AES-256-GCM + scrypt), file 0600 | Same — root fix, all modes |
| R9 | `sol.send()` library had no gate | Gated inside the library (same as EVM `send()`) | Same — root fix, all modes |
| R10 | One approval = permanent domain allowlist; turbo auto-allowlisted | Approvals never persist a domain (one-time only) | Balanced: persist only with explicit `--persist-domain`. Turbo: auto-allowlist kept, logged |
| R11 | Quest `eval`/`api` steps (arbitrary JS/HTTP) unchecked | **Refused**, even with opt-in; faucet `claim()` forces scam check on | Allowed only with explicit `allow_eval: true` / `allow_api: true` in the quest file |
| R12 | Autopilot + radar auto-queue could run to unknown sites | Auto-queue off (findings stored for human review only); autopilot `follow`/`quests` need explicit `safe_allow_follow: true` / `safe_allow_quests: true` in `autopilot.yaml` | Old behaviour kept |
| R13 | Discord self-bot (user token) + chat context to external LLM | Discord **disabled**; external grind LLM **disabled** (local fallback only) | Discord needs explicit `social.discord_selfbot: true` in `policy.yaml` (default `false`) |

## Opt-ins (outside safe mode)

These settings exist so features keep working for operators who accept the
risk explicitly. None of them has any effect in safe mode.

```yaml
# policy.yaml
browser:
  ignore_https_errors: false   # true only if you sit behind a MITM proxy and accept it
  clipboard: true              # false to remove clipboard read/write
social:
  discord_selfbot: false       # true = allow the Discord user-token module
```

```yaml
# autopilot.yaml (safe mode only)
safe_allow_follow: false       # true = allow the follow module while in safe mode
safe_allow_quests: false       # true = allow the quest module while in safe mode
```

```yaml
# a quest file (balanced/turbo only; refused in safe mode)
allow_eval: true               # allow `eval` steps (arbitrary JS in the page)
allow_api: true                # allow `api` steps (arbitrary HTTP)
```

```bash
aa gate approve <id> <CODE> --persist-domain   # balanced only: also persist the domain
```

## What safe mode does NOT do

- It does not make a quest safe to import. A quest YAML from an unknown
  source can still describe clicks, forms and wallet connects — read every
  step before running it, in any mode.
- It does not price SPL token amounts in Solana gate summaries (no price
  source in the bridge). Raw units + recipients + instructions are shown;
  the approver judges the value.
- It does not maintain a list of known-bad domains. `domain_blocklist` in
  `policy.yaml` is deliberately empty by default — fill it from sources you
  trust. The blocklist is a hard block in every mode.
- It does not remove the need for `aa doctor` before funded work, or for a
  human code on every gate (exit `10` → `aa gate approve <id> <CODE>` →
  re-run the identical command).

## Quick start (sandbox)

```
aa mode safe
aa identity new sandbox --wallets 1   # fresh testnet-only identity
# fill only testnet gas; never import an existing wallet or seed
aa quest validate <quest>              # eval/api without opt-in fails here
aa quest run <quest> --dry             # lists steps, touches nothing
```
