# Aurora participation coin

A spec for the cryptocurrency layer on top of geogram/aurora. It rewards genuine
participation and deters spammers, while staying usable on a decentralized,
often-offline mesh (BLE, APRS, Reticulum) where casual and emergency messaging
must remain free.

This document is the single source of truth for formats and rules. Phase 1
(administrator authority log + offline-verifiable bearer tokens + wallet) is
implemented under `lib/src/services/coin/`; later phases (ATM chain, sanctions
enforcement, faucet, postage) are specified here and built incrementally.

## 1. Concepts and layers

A **coin** is its own organism, independent of any group. It is owned by a single
**administrator** and identified by the administrator's secp256k1 x-only pubkey
(`coinId`, shareable as an npub). Nodes opt in to a coin and, by doing so, agree
to accept that administrator's decisions.

Two layers per coin:

1. **Administrator authority layer** — a signed, incrementally indexed log of the
   administrator's monetary-policy decisions (issuance, grants, faucet rules, the
   trusted ATM set, sanctions). Verifiable offline and replay-resistant. Any node
   replays it to the same `CoinPolicy`. This is the "central bank" layer, but its
   power is transparent and auditable.

2. **ATM settlement layer** — a permissioned hash-linked blockchain maintained by
   ATM nodes that the administrator manually trusts. It records transactions
   (transfers, bearer-token redemptions, faucet grants, sanction records). This is
   what decentralizes balance-keeping instead of the administrator holding every
   balance.

**Money** is Chaumian ecash (Cashu-style BDHKE bearer tokens). The online ATM
path is preferred; bearer tokens are accepted offline when no ATM is reachable
(emergency case), with authenticity verified offline and double-spend reconciled
later.

**Spam** is handled separately, at messaging spend time, not in the coin. Casual
and emergency messaging is free up to a per-key allowance; only sustained volume
or advanced features require coin postage.

## 2. Identity and crypto

- Curve: secp256k1. Identities are x-only pubkeys (BIP-340), same as the rest of
  geogram (`lib/src/util/nostr_crypto.dart`).
- Point arithmetic for ecash lives in `lib/src/services/coin/coin_ec.dart` (scalar/
  point multiply, add/sub/negate, compressed SEC1 (de)serialization, hash-to-curve
  with the Cashu `Secp256k1_HashToCurve_Cashu_` domain separator, hash-to-scalar).
- Administrator decisions are signed NOSTR events (BIP-340 Schnorr).

## 3. Mint keyset (`coin_keyset.dart`)

The administrator runs the mint, which holds one keypair per **denomination**
(powers of two, default 2^0..2^20), so a blind signature binds the token's amount.

- Secret half `CoinMintKeys` (amount -> private scalar) never leaves the mint.
  Derived deterministically: `k_amount = sha256(seed || "/amount/counter") mod n`,
  retrying the counter on the (astronomically unlikely) zero.
- Public half `CoinKeyset` (amount -> public point `K = k*G`) is published in the
  authority log so wallets bootstrap entirely from the log.
- `keysetId = "00" + first 14 hex of sha256(sorted (amount||compressed-pubkey))`.
  Version byte `00`; pins exactly which keys a wallet trusts.

## 4. Bearer tokens — BDHKE + DLEQ (`bearer_token.dart`)

Wallet = Alice, Mint = Bob, per-amount key `k`, `K = k*G`.

```
blind:    Y = hashToCurve(secret);  B_ = Y + r*G            (r = random blinding scalar)
sign:     C_ = k*B_         (+ DLEQ proving same k as in K)
unblind:  C  = C_ - r*K = k*Y                               (bearer proof = (secret, C))
redeem:   mint checks C == k*Y          (mint knows k)
offline:  verifier re-blinds with r and checks the DLEQ against K (no k, no network)
```

**DLEQ** (mint proves `log_G(K) == log_{B_}(C_)`): pick nonce `rd`; `R1 = rd*G`,
`R2 = rd*B_`; `e = H(R1, R2, K, C_)`; `s = rd + e*k mod n`. Verifier recomputes
`R1 = s*G - e*K`, `R2 = s*B_ - e*C_` and checks `H(R1,R2,K,C_) == e`. Because the
token carries the blinding scalar `r`, a third party reconstructs `C_ = C + r*K`
and `B_ = Y + r*G` and verifies entirely offline — the "run checks offline to
others" property.

**Proof** (spendable token) fields: `a` amount, `id` keysetId, `secret` (hex x),
`C` (compressed hex), `r` (blinding scalar hex), `e`, `s`. A **BearerToken**
bundles proofs for one coin and serializes as `coin1<base64url(json)>`.

## 5. Administrator authority log (`authority_log.dart`)

Append-only signed log; NOSTR kind `1573`. Each entry carries tags
`["d", coinId]`, `["seq", "<index>"]`, and (except genesis) `["prev", <prevId>]`,
with the decision in `content`.

Reducer (`reduceAuthority`) applies an entry only if: kind/coin match, it is
signed by the master (`pubkey == coinId`), the signature verifies, its `seq` is
strictly greater than the last applied (replays/duplicates/stale ignored), and
any `prev` equals the last applied entry's id (chain integrity). This is the
replay resistance.

Decisions (`content.op`):

| op | meaning |
|---|---|
| `define` | genesis: name, symbol, decimals, embedded public `keyset` |
| `issue` | authorize minting `amount` more units into the pool |
| `grant` | give `amount` units directly to a pubkey (coinbase-style) |
| `faucet` | set automatic participation-faucet `rules` (opaque map) |
| `addAtm` / `revokeAtm` | manage the trusted ATM node set |
| `sanction` | record a sanction on a pubkey (level, until, clawback, proof) |
| `lift` | lift a sanction |
| `policy` | set the sanction ladder / free-tier policy (opaque map) |

Reduced state `CoinPolicy`: name/symbol/decimals, keyset, `totalIssued`,
`totalGranted`, `faucetRules`, `sanctionPolicy`, active ATM set, sanctions map,
`lastSeq`, `headId`.

## 6. ATM settlement chain (Phase 2 — implemented: `atm_chain.dart`)

- Permissioned, small validator set = the active ATMs from `CoinPolicy`.
- Block: `{ height, prevHash, txs[], atmSig }`. Hash-linked.
- Ordering: deterministic leader by height; other ATMs validate and counter-sign;
  if the leader is offline the next ATM takes over. BFT-lite hardening later.
- Transactions: transfer, bearer-redeem (swap a bearer proof for fresh proofs or a
  balance), faucet grant, sanction record.
- **Spent-secret index**: each redeemed token's `secret` is recorded; a second
  appearance is a double-spend (see §7).
- Online transfers are final once settled into a block (preferred path). Offline
  bearer transfers reconcile when an ATM is reached.

## 7. Double-spend detection and sanctions (Phase 3 — implemented: `fraud.dart` + `atm_chain.dart`)

**Self-proving fraud.** A bearer token carries a unique secret; each spend is a
record signed by the holder binding that token to exactly one recipient. Two
validly-signed spend records for the same token to different recipients form a
fraud proof anyone can verify with no trust. ATMs detect it via the spent-secret
index.

**Sanction ladder** (thresholds configurable via the `policy` decision, auto-
applied by ATMs, administrator can override/lift):

1. **Freeze** — time-boxed bar on sending/receiving the coin.
2. **Clawback / overcharge** — the double-spent value is charged against the
   offender's wallet; any shortfall becomes a debt cleared before transacting
   again. The recovered value reimburses the honest receiver of the invalidated
   token.
3. **Suspend** — indefinite bar on sending/receiving the coin, until the
   administrator lifts it.

**Public shaming.** Sanctions are published in a signed, evidence-backed list
scoped to the coin (fraud proof attached). Honest nodes refuse tokens from/to a
sanctioned npub. Because every sanction carries an irrefutable signed fraud proof
and is scoped to one coin, the shaming is fair and verifiable, not arbitrary
censorship. Only the administrator lifts a sanction.

This is what makes accepting bearer tokens offline safe enough: cheating is
caught, clawed back, the victim reimbursed, and the cheater frozen or suspended,
so double-spending is economically irrational.

## 8. Participation faucet (Phase 4 — implemented: `faucet.dart`)

The administrator's `faucet` rules define which participation is rewarded and at
what rate. Earning, in priority order:

1. **Recycled postage (primary)** — postage spent on a message flows to the relays
   that carried it and the recipient. Most earning is collecting what others spent.
2. **Capped useful-work issuance** — net-new units granted for verifiable relay /
   store-and-forward delivery receipts (signed by the *recipient*, not the relayer)
   and indexer uptime; capped per period to bound Sybil farming.
3. **Small bootstrap faucet** — a tiny grant so a newcomer can send their first
   above-free-tier message; sized by anchored trust flow from the community's
   anchors so spammer cliques with no inbound anchor edge earn ~nothing.

## 9. Spam and the free emergency tier (implemented + wired)

The coin-side primitives (free-tier rate meter + consumable postage) live in
`lib/src/services/coin/postage.dart`. They are now wired into the shared inbound-event
gate: `SpamPolicy` (`lib/src/services/social/spam.dart`) takes an optional
coin-agnostic `postageValidator` callback and a `requirePostage` flag, so it stays
decoupled from the coin layer. `lib/src/services/coin/postage_gate.dart` supplies the
validator and the on-event convention (a `["postage", base64url(json)]` tag): an
event over the free rate limit is accepted if it carries valid postage payable to
the relay, and advanced-feature events must carry it. The postage is settled and
double-spend-checked when the relay later redeems it on the ATM chain.

- Every identity gets a free low-bandwidth messaging allowance (emergency +
  casual), enforced by a per-key rate limit. A distress message is never gated
  behind coins.
- Above the allowance, or for advanced features (large files, priority relay, wide
  broadcast), a message must carry consumable coin **postage**.
- Relays reserve a slice of bandwidth for untrusted free traffic and throttle it
  first under load, so a swarm of fresh keys degrades gracefully and a brand-new
  install can still get a distress message out.

## 10. Reuse map

| Need | Code |
|---|---|
| secp256k1 / Schnorr / hashing | `lib/src/util/nostr_crypto.dart`, `pointycastle` |
| ecash point arithmetic | `lib/src/services/coin/coin_ec.dart` |
| signed op-log + reducer pattern | mirrors `lib/services/folders/folder_event.dart` + `folder_state.dart` |
| always-on node role for mint/ATM | `lib/src/services/files/capacity_governor.dart`, `lib/src/services/social/relay_role.dart` |
| postage gate + rate limit | `lib/src/services/social/spam.dart` |
| offline delivery / reconciliation | `lib/src/services/social/store_forward.dart` |
| sqlite store pattern | `lib/wapp/geoui/activity_archive.dart` |

## 11. Status

All coin logic lives in `lib/src/services/coin/` (host-generic, no edits to shared
host files). 45 tests in `test/coin/`, analyzer clean.

- Phase 0 (done): this document.
- Phase 1 (done): `coin_ec.dart`, `coin_keyset.dart`, `bearer_token.dart`,
  `authority_log.dart`, `wallet.dart` — BDHKE round-trip, offline DLEQ verify,
  tamper rejection, denomination binding, authority replay resistance /
  forged-issuer rejection / chain-link integrity, wallet storage.
- Phase 2 (done): `atm_chain.dart` — hash-linked blocks, leader-by-height +
  counter-sign, transfer/redeem/grant, spent-secret index, replication.
- Phase 3 (done): `fraud.dart` + `atm_chain.dart` — spend records, self-proving
  fraud proofs, sanction ladder (freeze -> clawback + victim reimbursement ->
  suspension), idempotent adjudication.
- Phase 4 (done): `postage.dart` (free-tier meter + consumable postage) and
  `faucet.dart` (capped useful-work issuance + trust-sized bootstrap).
- Phase 5 (done): `coin_service.dart` — `CoinService` (wallet/user facade:
  balances, online transfer, offline bearer hand-off, postage, redeem) and
  `CoinAdmin` (authority-decision emitter with correct seq/prev chaining).
- Integration (done): `mint.dart` — `Mint` with redeem and exact change-making
  `swap` (split/merge); postage wired into `spam.dart` via `postage_gate.dart`
  (coin-agnostic callback, backward-compatible); `node_policy.dart` — merged
  effective sanction status (authority-log OR chain-derived, admin lift overrides
  a chain sanction whose offense predates the lift).
- Remaining (still deferred): transport of blocks/tokens over
  `store_forward.dart`/Reticulum, and the wapp UI. These touch files under active
  concurrent edit (relay/transport, wapp_page), so they are left for a focused
  follow-up.

Total: 60 tests in `test/coin/`, analyzer clean across `lib/src/services/coin/` and
`lib/src/services/social/`.
