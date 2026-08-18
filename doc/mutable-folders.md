# Mutable folders — identity, permissions, and safe multi-hosting

A **mutable folder** is an IPNS-like, key-addressed directory whose contents are a
signed, append-only log of NOSTR events. It points at immutable, content-addressed
files (each named by its SHA-256) and can be re-hosted and seeded by any number of
devices torrent-style. This document defines **who can read, who can host, and who
can write**, so the capability boundaries are never confused.

Code: [`folder_event.dart`](../../aurora/lib/services/folders/folder_event.dart),
[`folder_state.dart`](../../aurora/lib/services/folders/folder_state.dart),
[`folder_service.dart`](../../aurora/lib/services/folders/folder_service.dart).
See also [file-sharing.md](file-sharing.md) §7 and [dht.md](dht.md).

## 1. Identity

A folder is a secp256k1 keypair.

- `folderId` = the master **public** key (x-only, 64 hex). Its npub
  (`npub1…`) is the permanent, shareable address.
- The shareable address is a **public key only**. Sharing it lets others read and
  host the folder. It does NOT let them change it.
- The matching master **private** key is the folder's write root. It is held only by
  the owner and is the single most sensitive secret of the folder.

## 2. The two event kinds

- `KEYSET` (kind `30564`, NIP-33 parameterized-replaceable, `d = folderId`).
  Lists the authorized admins: `{"admins":[{p,role,a,r?}]}` where `a`/`r` are the
  unix-second add/revoke timestamps. A keyset is honoured **only when signed by the
  master** (`keyset.pubkey == folderId`), and the relay keeps only the newest one
  per author — so **only the owner decides who may write**.
- `OP` (kind `1064`, regular/append-only, tagged `d = folderId`). One edit each:
  `addFile` / `rmFile` / `setMeta` / `link` / `unlink`.

## 3. Authorization — who can WRITE

`reduceFolder` (folder_state.dart) applies an op **only if all three hold**:

1. the op carries the folder's `d` tag,
2. its signature verifies, and
3. its author was authorized **at the op's `created_at`** — either the master
   (`author == folderId`), or an admin whose keyset entry covers that timestamp
   (`addedAt <= ts < revokedAt`).

Two consequences:

- **Admins sign with their own profile key, never the master key.** The owner grants
  write access by adding an admin's npub to the master-signed keyset; that admin then
  signs ops with their personal key. The master private key never leaves the owner.
- **Revocation is forward-only.** Removing an admin stops their *future* edits; their
  earlier, legitimately-signed edits remain (they were valid when made).

## 4. Authorization — who can READ and HOST

**Nobody needs a key to read or to host.** Anyone holding the public `folderId`:

- fetches the already-signed keyset + op events (from a provider's relay or an
  indexer), reduces them to the current `name → (sha256, metadata)` map,
- fetches each file by its sha over Reticulum, and **verifies it against the hash**,
- can then **re-serve those bytes and relay those signed events** to others.

This is safe because a host proves nothing: file integrity comes from the SHA-256, and
edit integrity comes from the events' own signatures checked against the master-signed
keyset. A malicious host can at worst serve bytes that fail the hash (a wasted round
trip) or replay events that the reducer already authorizes — it can never forge a new
edit, because it does not hold the master or an admin key.

## 5. Multi-hosting — share the folderId, never the private key

To make a folder durable and removes single-device dependency, **many devices host the
same folderId**, each an interchangeable provider of identical bytes:

- A device becomes an additional provider by **subscribing to the folderId**,
  downloading the content, pinning it, and auto-seeding. It publishes provider records
  for the same shas and relays the same signed op-log. **No key is involved.** This is
  the torrent-style case and the correct way to "host the same folder from another
  device".
- **Do NOT copy the disk folder's hidden key file (`.folder.json`) to host.** That file
  contains the master **private** key. Copying it does not just let the other device
  host — it silently grants that device authority to **sign edits**, i.e. full write
  control. Hosting must never require, and must never leak, the write key.

### Owner moving to a new device (the only time the private key moves)

If the **owner** wants to keep *writing* to the folder from a new device, that is a
deliberate transfer of the master private key — an explicit, clearly-warned,
owner-only **export/import** ("this gives the new device permission to change the
folder"). It is a distinct operation from hosting and must never be a side effect of
sharing or seeding.

## 6. Summary

| Capability            | Requires                                         |
|-----------------------|--------------------------------------------------|
| Read the folder       | the public `folderId` (npub)                     |
| Host / seed the bytes | the public `folderId` + the content (no key)     |
| Edit the folder       | be the master, or an admin in the master keyset  |
| Add/remove admins     | the master **private** key (owner only)          |
| Move write control    | explicit owner export of the master private key  |

Share the folderId freely. Grant editing by adding a revocable admin. Guard the master
private key — it is the only thing that can change the folder, and it should leave the
owner's device only as a deliberate, warned migration.
