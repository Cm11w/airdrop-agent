# Safety model

## Assets in scope

Agent wallets (burners), social sessions, email inboxes, and the vault passphrase. The operator's
main seed is never imported by default.

## Vault

- AES-256-GCM, scrypt KDF, per-entry random nonce, AAD = `kind/name`.
- Renaming or moving a blob between kinds fails authentication (no silent decrypt of the wrong key).
- `VAULT_PASSWORD` lives in `.env` (0600) or `VAULT_PASSWORD_FILE`. Lose it and the keys are gone —
  export a bundle and store it offline.
- Export is ciphertext only; import writes atomically.

## Approval gates

- 6-char code, hash-bound to the payload, TTL 12h, single use.
- Delivered only to the operator's Telegram bot. The page cannot choose the code.
- A gate covers: chain, recipient, value, calldata, selector, decoded call, balance delta, domain.
- Unlimited approvals always gate, in every mode.
- Permit/Permit2/Seaport orders gate unless turbo explicitly sets `allow_permits`.
- Approving a gate does NOT permanently allowlist its domain, except: in turbo
  (auto-allowlist is a turbo feature, logged when it happens) and in balanced
  only when the gate payload explicitly opts in (`persist_domain: true`) or the
  operator passes `aa gate approve --persist-domain`. In safe mode an approval
  is always one-time only — the domain is never remembered. Use `aa allow add`
  for a deliberate, permanent allowlist entry.

## Browser hardening

- `ignore_https_errors` defaults to **false** (policy.yaml `browser:` block): a
  bad/expired certificate or a MITM proxy fails loudly instead of being silently
  accepted. Safe mode forces it false whatever the config says.
- Clipboard permissions (`clipboard-read` / `clipboard-write`) are granted only
  outside safe mode and only when `browser.clipboard` is true (default true,
  the pre-fix behaviour). Safe mode runs with no clipboard permissions at all.

## Hard blocks (no mode overrides)

| block | why |
|---|---|
| KILL file | operator stop |
| `eth_sign` blind hash | unreadable payload |
| unlimited approval | drainer pattern |
| blocklisted address | known bad |
| blocklisted domain (`domain_blocklist` in policy.yaml) | known bad — navigation refused in every mode |
| scam verdict `bad` | drainer domain — safe: navigation refused; balanced: explicit gate approval first; turbo: warning only, navigates anyway |
| drainer words in page text (`seed phrase`, `validate wallet`, …) | safe: run aborted after navigation; balanced/turbo: warning + explicit gate approval to continue |
| value over per-tx cap | runaway amount |
| daily cap | runaway day |
| contract not allowlisted on mainnet | unknown target |

## Spend caps

Per chain: `max_tx_native`, `max_daily_native`, `max_gas_native`, in native units, converted with the
chain's `native_decimals` (Solana = 9, not 18). Gas is checked against the gas cap before signing.
Turbo widens caps per chain but never removes the hard blocks.

## Scam heuristics

`scam_check` inspects scheme, registrable domain, punycode, suspicious TLD, hyphen count, brand
embedding/typosquat (Levenshtein 1), drain-keywords in page text, and optional RDAP age. Verdict:
`bad` never auto-connects, `warn` gates, `ok` may auto-connect only when the domain is allowlisted
(or auto-allowlist is on in turbo).

- **Domain blocklist.** `domain_blocklist` in policy.yaml is the operator-maintained
  list of known-bad domains (subdomains included). It is enforced as a hard block:
  the browser refuses to navigate there in every mode, and `check_url` reports
  verdict `bad`. It ships empty on purpose — fill it from sources you trust.
  The in-code `BAD_DOMAINS` set in `aa/scam_check.py` is intentionally left empty
  for the same reason (a hardcoded list goes stale); do not populate it.
- **Page-text scan.** `check_page_text` (drainer words such as `seed phrase`,
  `validate wallet`, `approve all`) now runs after every `goto` with scam
  checking on — it used to be dead code with zero callers. A `bad` page-text
  verdict aborts the run in safe mode and requires an explicit gate approval
  to continue in balanced/turbo, even when the URL itself looked clean.
- **Navigation by verdict.** `bad` URL verdict: safe refuses to navigate,
  balanced needs an explicit gate approval before navigating, turbo only warns
  and navigates anyway (old behaviour, kept deliberately).

## Redaction

Every envelope line passes `log.redact`: 64-hex keys, Telegram bot tokens, Discord/X/Telethon tokens,
proxies, mnemonics, and literal values of sensitive env vars. Vault paths and addresses stay visible
on purpose.

## Operational

- Dedicated social accounts, never the main identity.
- Dedicated email inbox; the agent reads its own IMAP, not yours.
- One residential proxy per identity in `BROWSER_PROXY` for anything funded.
- Autopilot `chat` and `campaign` off by default: both cost (ToS, gas).
- `aa doctor` before mainnet; `aa mode safe` while auditing a new site.
