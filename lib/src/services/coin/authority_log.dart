/*
 * authority_log — the administrator's signed monetary-policy log for a coin.
 *
 * A coin is an organism owned by ONE administrator, identified by the admin's
 * x-only pubkey (coinId / npub). Nodes opt in to a coin and agree to accept the
 * administrator's decisions. Those decisions form an append-only log, each entry
 * signed by the administrator and carrying a strictly increasing sequence index
 * (and a hash-link to the previous entry) so the log is verifiable offline and
 * resistant to replay/reordering — exactly the property the user asked for.
 *
 * This mirrors the mutable-folder pattern (folder_event.dart + folder_state.dart):
 * signed events + a deterministic reducer any node can replay to the same state.
 * Here the reducer yields CoinPolicy: supply, faucet rules, the trusted ATM set,
 * and sanctions. The ATM permissioned ledger (transactions) is a separate layer.
 *
 * Pure/headless: nostr_event + nostr_crypto + dart:convert + coin_keyset.
 */
import 'dart:convert';

import '../../util/nostr_crypto.dart';
import '../../util/nostr_event.dart';
import 'coin_keyset.dart';

/// Append-only administrator decision; the full log is retained and replayed.
const int kKindCoinAuthority = 1573;

const String kCoinTag = 'd'; // carries coinId
const String kSeqTag = 'seq'; // strictly-increasing decimal index
const String kPrevTag = 'prev'; // id of the previous authority entry

int _nowSec() => DateTime.now().millisecondsSinceEpoch ~/ 1000;

/// Build a signed authority entry. Must be signed by the coin master (its
/// pubkey == coinId). [seq] must be strictly greater than the previous entry's,
/// and [prevId] should be the previous entry's id (null only for the genesis).
NostrEvent buildAuthority(String adminPrivHex, String coinId, int seq,
    Map<String, dynamic> op,
    {String? prevId, int? createdAt}) {
  final e = NostrEvent(
    pubkey: NostrCrypto.derivePublicKey(adminPrivHex),
    createdAt: createdAt ?? _nowSec(),
    kind: kKindCoinAuthority,
    tags: [
      [kCoinTag, coinId],
      [kSeqTag, '$seq'],
      if (prevId != null) [kPrevTag, prevId],
    ],
    content: jsonEncode(op),
  );
  e.sign(adminPrivHex);
  return e;
}

// ── decision payload builders ───────────────────────────────────────────────

/// Genesis: define the coin and publish its public keyset so wallets bootstrap
/// entirely from the log.
Map<String, dynamic> opDefine(
        {required String name,
        required String symbol,
        int decimals = 0,
        required CoinKeyset keyset}) =>
    {
      'op': 'define',
      'name': name,
      'symbol': symbol,
      'decimals': decimals,
      'keyset': keyset.toJson(),
    };

/// Authorize minting [amount] more units into the pool.
Map<String, dynamic> opIssue(int amount) => {'op': 'issue', 'amount': amount};

/// Directly grant [amount] units to an npub/pubkey (coinbase-style).
Map<String, dynamic> opGrant(String toPubHex, int amount, {String? reason}) =>
    {'op': 'grant', 'to': toPubHex, 'amount': amount, 'reason': ?reason};

/// Set the automatic participation-faucet rules (opaque rules map: which kinds
/// of participation are rewarded and at what rate). Interpreted by the faucet.
Map<String, dynamic> opSetFaucet(Map<String, dynamic> rules) =>
    {'op': 'faucet', 'rules': rules};

/// Add a manually-trusted ATM (settlement) node.
Map<String, dynamic> opAddAtm(String pubHex) => {'op': 'addAtm', 'p': pubHex};

/// Revoke a previously-trusted ATM node.
Map<String, dynamic> opRevokeAtm(String pubHex) =>
    {'op': 'revokeAtm', 'p': pubHex};

/// Sanction levels in the double-spend ladder.
class SanctionLevel {
  static const String freeze = 'freeze'; // time-boxed bar on sending/receiving
  static const String suspend = 'suspend'; // indefinite, until lifted
}

/// Record a sanction against [pubHex]. [until] (unix secs) applies to freezes;
/// [clawback] is the overcharged value; [proofId] references the fraud proof.
Map<String, dynamic> opSanction(String pubHex, String level,
        {int? until, int? clawback, String? proofId}) =>
    {
      'op': 'sanction',
      'p': pubHex,
      'level': level,
      'until': ?until,
      'clawback': ?clawback,
      'proof': ?proofId,
    };

/// Lift an existing sanction on [pubHex].
Map<String, dynamic> opLift(String pubHex) => {'op': 'lift', 'p': pubHex};

/// Configure the sanction ladder / free-tier policy (opaque to the reducer; the
/// enforcement layer reads it). Stored as-is for transparency.
Map<String, dynamic> opSetPolicy(Map<String, dynamic> policy) =>
    {'op': 'policy', 'policy': policy};

// ── reduced state ───────────────────────────────────────────────────────────

class AtmEntry {
  final String pubkey;
  final int addedAt;
  final int? revokedAt;
  const AtmEntry(this.pubkey, this.addedAt, [this.revokedAt]);

  bool activeAt(int ts) =>
      ts >= addedAt && (revokedAt == null || ts < revokedAt!);

  Map<String, dynamic> toJson() => {
        'p': pubkey,
        'a': addedAt,
        if (revokedAt != null) 'r': revokedAt,
      };
}

class SanctionState {
  final String pubkey;
  final String level; // freeze | suspend
  final int? until; // freeze expiry (unix secs)
  final int clawback; // outstanding overcharge owed
  final String? proofId;
  final int at; // when applied

  const SanctionState(this.pubkey, this.level,
      {this.until, this.clawback = 0, this.proofId, required this.at});

  /// Still in force at [ts]? Suspensions never auto-expire; freezes do.
  bool activeAt(int ts) {
    if (level == SanctionLevel.suspend) return true;
    return until == null || ts < until!;
  }

  Map<String, dynamic> toJson() => {
        'p': pubkey,
        'level': level,
        if (until != null) 'until': until,
        if (clawback != 0) 'clawback': clawback,
        if (proofId != null) 'proof': proofId,
        'at': at,
      };
}

/// The deterministic reduction of an authority log.
class CoinPolicy {
  final String coinId;
  String? name;
  String? symbol;
  int decimals = 0;
  CoinKeyset? keyset;
  int totalIssued = 0; // sum of issue ops
  int totalGranted = 0; // sum of grant ops
  Map<String, dynamic> faucetRules = const {};
  Map<String, dynamic> sanctionPolicy = const {};
  final Map<String, AtmEntry> atms = {}; // pubkey -> entry
  final Map<String, SanctionState> sanctions = {}; // pubkey -> sanction
  final Map<String, int> lifts = {}; // pubkey -> created_at of the admin's lift
  int lastSeq = -1;
  String? headId;

  CoinPolicy(this.coinId);

  /// ATM nodes trusted right now (default: at current time).
  List<AtmEntry> activeAtms([int? ts]) {
    final t = ts ?? _nowSec();
    return [for (final a in atms.values) if (a.activeAt(t)) a];
  }

  /// Is [pubHex] barred from transacting at [ts]?
  bool isSanctioned(String pubHex, [int? ts]) {
    final s = sanctions[pubHex];
    return s != null && s.activeAt(ts ?? _nowSec());
  }

  Map<String, dynamic> toJson() => {
        'coinId': coinId,
        if (name != null) 'name': name,
        if (symbol != null) 'symbol': symbol,
        'decimals': decimals,
        if (keyset != null) 'keysetId': keyset!.keysetId,
        'totalIssued': totalIssued,
        'totalGranted': totalGranted,
        'faucetRules': faucetRules,
        'sanctionPolicy': sanctionPolicy,
        'atms': [for (final a in atms.values) a.toJson()],
        'sanctions': [for (final s in sanctions.values) s.toJson()],
        'lastSeq': lastSeq,
        if (headId != null) 'headId': headId,
      };
}

int? _seqOf(NostrEvent e) {
  for (final t in e.tags) {
    if (t.length >= 2 && t[0] == kSeqTag) return int.tryParse(t[1]);
  }
  return null;
}

String? _prevOf(NostrEvent e) {
  for (final t in e.tags) {
    if (t.length >= 2 && t[0] == kPrevTag) return t[1];
  }
  return null;
}

bool _hasCoinTag(NostrEvent e, String coinId) {
  for (final t in e.tags) {
    if (t.length >= 2 && t[0] == kCoinTag && t[1] == coinId) return true;
  }
  return false;
}

/// Reduce a coin's authority [log] into its current [CoinPolicy].
///
/// An entry is applied only if: it is the right kind and coin-tagged, signed by
/// the coin master (pubkey == coinId), its signature verifies, its sequence is
/// strictly greater than the last applied (so replays/duplicates/old entries are
/// ignored), and — when it carries a `prev` — that prev matches the last applied
/// entry's id (chain integrity). This is what makes the log replay-resistant.
CoinPolicy reduceAuthority(String coinId, List<NostrEvent> log) {
  final policy = CoinPolicy(coinId);

  // Only the master's well-formed, verified entries, oldest seq first.
  final ordered = [
    for (final e in log)
      if (e.kind == kKindCoinAuthority &&
          e.pubkey == coinId &&
          _hasCoinTag(e, coinId) &&
          _seqOf(e) != null &&
          e.verify())
        e
  ]..sort((a, b) {
      final d = _seqOf(a)!.compareTo(_seqOf(b)!);
      if (d != 0) return d;
      return (a.id ?? '').compareTo(b.id ?? '');
    });

  for (final e in ordered) {
    final seq = _seqOf(e)!;
    if (seq <= policy.lastSeq) continue; // replay / duplicate / stale
    final prev = _prevOf(e);
    if (prev != null && prev != policy.headId) continue; // broken chain link
    Object? payload;
    try {
      payload = jsonDecode(e.content);
    } catch (_) {
      continue;
    }
    if (payload is! Map) continue;
    _apply(policy, payload, e.createdAt);
    policy.lastSeq = seq;
    policy.headId = e.id;
  }
  return policy;
}

void _apply(CoinPolicy p, Map op, int ts) {
  switch (op['op']) {
    case 'define':
      p.name = op['name'] as String?;
      p.symbol = op['symbol'] as String?;
      if (op['decimals'] is int) p.decimals = op['decimals'] as int;
      final ks = CoinKeyset.fromJson(op['keyset']);
      if (ks != null) p.keyset = ks;
      break;
    case 'issue':
      final a = op['amount'];
      if (a is int && a > 0) p.totalIssued += a;
      break;
    case 'grant':
      final a = op['amount'];
      if (a is int && a > 0) p.totalGranted += a;
      break;
    case 'faucet':
      final r = op['rules'];
      if (r is Map) p.faucetRules = Map<String, dynamic>.from(r);
      break;
    case 'addAtm':
      final pub = op['p'];
      if (pub is String && pub.isNotEmpty) {
        // Re-adding a previously-revoked node starts a fresh active window.
        p.atms[pub] = AtmEntry(pub, ts);
      }
      break;
    case 'revokeAtm':
      final pub = op['p'];
      if (pub is String) {
        final existing = p.atms[pub];
        if (existing != null && existing.revokedAt == null) {
          p.atms[pub] = AtmEntry(existing.pubkey, existing.addedAt, ts);
        }
      }
      break;
    case 'sanction':
      final pub = op['p'];
      final level = op['level'];
      if (pub is String && pub.isNotEmpty && level is String) {
        p.sanctions[pub] = SanctionState(
          pub,
          level,
          until: op['until'] is int ? op['until'] as int : null,
          clawback: op['clawback'] is int ? op['clawback'] as int : 0,
          proofId: op['proof'] as String?,
          at: ts,
        );
      }
      break;
    case 'lift':
      final pub = op['p'];
      if (pub is String) {
        p.sanctions.remove(pub);
        // Remember the lift time so it can also override a chain-derived
        // sanction whose offense predates the lift (see node_policy.dart).
        p.lifts[pub] = ts;
      }
      break;
    case 'policy':
      final pol = op['policy'];
      if (pol is Map) p.sanctionPolicy = Map<String, dynamic>.from(pol);
      break;
    default:
      break;
  }
}
