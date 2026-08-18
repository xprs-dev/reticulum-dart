/*
 * atm_chain — the ATM settlement layer: a small permissioned blockchain that
 * records a coin's transactions, maintained by the ATM nodes the administrator
 * manually trusts. This is what decentralizes balance-keeping (the administrator
 * does not hold every balance) and gives the canonical, double-spend-safe ledger
 * the online path settles into.
 *
 * Blocks are hash-linked and signed by a leader chosen deterministically by
 * height from the trusted ATM set; other ATMs validate and may counter-sign.
 * A deterministic reducer replays the chain into AccountState (balances, the
 * spent-secret index, and used transfer/grant nonces) — any node holding the
 * blocks computes the same balances.
 *
 * Transactions:
 *   transfer  — account A -> B, signed by A (preferred online path)
 *   redeem    — settle a bearer Proof into B's account; verified offline by DLEQ
 *               against the published keyset, secret recorded so it can't be
 *               redeemed twice (the basis of double-spend detection)
 *   grant     — coinbase credit authorized by the administrator (faucet/issuance)
 *
 * Pure/headless: nostr_crypto + bearer_token + coin_keyset + dart:convert.
 */
import 'dart:convert';

import '../../util/nostr_crypto.dart';
import 'authority_log.dart' show SanctionState, SanctionLevel;
import 'bearer_token.dart';
import 'coin_keyset.dart';
import 'fraud.dart';

const String _genesisPrev =
    '0000000000000000000000000000000000000000000000000000000000000000';

int _nowSec() => DateTime.now().millisecondsSinceEpoch ~/ 1000;

/// Canonical JSON with recursively sorted keys, so a structure hashes/signs the
/// same regardless of map insertion order (e.g. after a JSON round-trip).
String canonicalJson(Object? value) {
  final buf = StringBuffer();
  _writeCanon(buf, value);
  return buf.toString();
}

void _writeCanon(StringBuffer buf, Object? v) {
  if (v is Map) {
    final keys = v.keys.map((e) => e.toString()).toList()..sort();
    buf.write('{');
    for (var i = 0; i < keys.length; i++) {
      if (i > 0) buf.write(',');
      buf.write(jsonEncode(keys[i]));
      buf.write(':');
      _writeCanon(buf, v[keys[i]]);
    }
    buf.write('}');
  } else if (v is List) {
    buf.write('[');
    for (var i = 0; i < v.length; i++) {
      if (i > 0) buf.write(',');
      _writeCanon(buf, v[i]);
    }
    buf.write(']');
  } else {
    buf.write(jsonEncode(v));
  }
}

// ── transactions ────────────────────────────────────────────────────────────

/// The message a tx signature commits to (excludes the signature itself).
String _txSigningHash(String coinId, Map<String, dynamic> body) =>
    NostrCrypto.sha256Hash('$coinId|${canonicalJson(body)}');

/// transfer A -> B, signed by A.
Map<String, dynamic> buildTransferTx(
    String coinId, String fromPriv, String to, int amount, String nonce) {
  final from = NostrCrypto.derivePublicKey(fromPriv);
  final body = {
    'type': 'transfer',
    'from': from,
    'to': to,
    'amount': amount,
    'nonce': nonce,
  };
  final sig = NostrCrypto.schnorrSign(_txSigningHash(coinId, body), fromPriv);
  return {...body, 'sig': sig};
}

/// redeem a bearer [proof] into [toPriv]'s account, signed by the recipient.
/// [spend] is the optional signed offline-handoff record proving who gave the
/// token to the redeemer; carrying it lets the chain attribute a later
/// double-spend to the giver.
Map<String, dynamic> buildRedeemTx(String coinId, String toPriv, Proof proof,
    {SpendRecord? spend}) {
  final to = NostrCrypto.derivePublicKey(toPriv);
  final body = {
    'type': 'redeem',
    'to': to,
    'proof': proof.toJson(),
    if (spend != null) 'spend': spend.toJson(),
  };
  final sig = NostrCrypto.schnorrSign(_txSigningHash(coinId, body), toPriv);
  return {...body, 'sig': sig};
}

/// fraud tx: self-proving double-spend evidence (two conflicting spend records).
/// Needs no signature — its validity is the FraudProof plus on-chain settlement
/// of the disputed secret. Any ATM may include it.
Map<String, dynamic> buildFraudTx(FraudProof proof) =>
    {'type': 'fraud', 'proof': proof.toJson()};

/// grant (coinbase) credit to [to], signed by the administrator (coinId).
Map<String, dynamic> buildGrantTx(
    String coinId, String adminPriv, String to, int amount, String nonce) {
  final body = {
    'type': 'grant',
    'to': to,
    'amount': amount,
    'nonce': nonce,
  };
  final sig = NostrCrypto.schnorrSign(_txSigningHash(coinId, body), adminPriv);
  return {...body, 'sig': sig};
}

// ── blocks ──────────────────────────────────────────────────────────────────

class AtmBlock {
  final String coinId;
  final int height;
  final String prevHash;
  final List<Map<String, dynamic>> txs;
  final int time;
  final String leader; // ATM pubkey that produced the block
  final String sig; // leader signature over [hash]
  final List<Map<String, String>> cosigs; // other ATM counter-signatures

  AtmBlock({
    required this.coinId,
    required this.height,
    required this.prevHash,
    required this.txs,
    required this.time,
    required this.leader,
    required this.sig,
    this.cosigs = const [],
  });

  /// Hash over the block's content (everything except signatures), as hex.
  String get hash => NostrCrypto.sha256Hash(canonicalJson({
        'coinId': coinId,
        'height': height,
        'prevHash': prevHash,
        'txs': txs,
        'time': time,
        'leader': leader,
      }));

  Map<String, dynamic> toJson() => {
        'coinId': coinId,
        'height': height,
        'prevHash': prevHash,
        'txs': txs,
        'time': time,
        'leader': leader,
        'sig': sig,
        'cosigs': cosigs,
      };

  static AtmBlock? fromJson(Object? o) {
    if (o is! Map) return null;
    try {
      return AtmBlock(
        coinId: o['coinId'] as String,
        height: o['height'] as int,
        prevHash: o['prevHash'] as String,
        txs: [
          for (final t in (o['txs'] as List)) Map<String, dynamic>.from(t as Map)
        ],
        time: o['time'] as int,
        leader: o['leader'] as String,
        sig: o['sig'] as String,
        cosigs: [
          for (final c in (o['cosigs'] as List? ?? const []))
            Map<String, String>.from(c as Map)
        ],
      );
    } catch (_) {
      return null;
    }
  }
}

// ── reduced state ───────────────────────────────────────────────────────────

class AccountState {
  final Map<String, int> balances = {};
  final Set<String> spentSecrets = {}; // redeemed bearer-token secrets
  final Set<String> usedNonces = {}; // "signer:nonce" for transfer/grant
  final Map<String, String> redeemedTo = {}; // secret -> recipient that collected
  final Map<String, int> redeemedAmount = {}; // secret -> value collected
  final Map<String, SanctionState> sanctions = {}; // culprit -> sanction
  final Map<String, int> offenses = {}; // culprit -> double-spend count
  final Set<String> adjudicated = {}; // fraud secrets already handled (idempotent)
  int height = -1;
  String headHash = _genesisPrev;

  int balanceOf(String pub) => balances[pub] ?? 0;
  int debtOf(String pub) => sanctions[pub]?.clawback ?? 0;
  bool isSanctioned(String pub, int ts) {
    final s = sanctions[pub];
    return s != null && s.activeAt(ts);
  }

  AccountState clone() {
    final c = AccountState()
      ..height = height
      ..headHash = headHash;
    c.balances.addAll(balances);
    c.spentSecrets.addAll(spentSecrets);
    c.usedNonces.addAll(usedNonces);
    c.redeemedTo.addAll(redeemedTo);
    c.redeemedAmount.addAll(redeemedAmount);
    c.sanctions.addAll(sanctions);
    c.offenses.addAll(offenses);
    c.adjudicated.addAll(adjudicated);
    return c;
  }

  Map<String, dynamic> toJson() => {
        'height': height,
        'headHash': headHash,
        'balances': balances,
        'spent': spentSecrets.length,
        'sanctions': [for (final s in sanctions.values) s.toJson()],
      };
}

// ── chain ───────────────────────────────────────────────────────────────────

class AtmChain {
  final String coinId;
  final CoinKeyset keyset;
  final List<String> validators; // trusted ATM pubkeys (sorted, stable)
  final SanctionPolicy sanctionPolicy;
  final List<AtmBlock> blocks = [];

  AtmChain(this.coinId, this.keyset, List<String> validators,
      {this.sanctionPolicy = const SanctionPolicy()})
      : validators = [...validators]..sort();

  /// The ATM expected to lead block [height].
  String leaderFor(int height) => validators[height % validators.length];

  AtmBlock? get head => blocks.isEmpty ? null : blocks.last;

  /// Current reduced account state (replay of all blocks).
  AccountState get state {
    var s = AccountState();
    for (final b in blocks) {
      final next = _applyBlock(s, b);
      if (next == null) break; // should not happen: only valid blocks are kept
      next
        ..height = b.height
        ..headHash = b.hash;
      s = next;
    }
    return s;
  }

  /// Build, sign, validate and append the next block carrying [txs]. The signer
  /// must be the expected leader for the next height. Returns the block, or null
  /// if the leader is wrong or any tx is invalid against current state.
  AtmBlock? produceBlock(String leaderPriv, List<Map<String, dynamic>> txs,
      {int? time}) {
    final height = (head?.height ?? -1) + 1;
    final leaderPub = NostrCrypto.derivePublicKey(leaderPriv);
    if (leaderPub != leaderFor(height)) return null; // not this ATM's turn
    // All txs must apply cleanly on top of current state.
    if (_applyTxs(state, txs) == null) return null;
    final prevHash = head?.hash ?? _genesisPrev;
    final draft = AtmBlock(
      coinId: coinId,
      height: height,
      prevHash: prevHash,
      txs: txs,
      time: time ?? _nowSec(),
      leader: leaderPub,
      sig: '',
    );
    final sig = NostrCrypto.schnorrSign(draft.hash, leaderPriv);
    final block = AtmBlock(
      coinId: coinId,
      height: height,
      prevHash: prevHash,
      txs: txs,
      time: draft.time,
      leader: leaderPub,
      sig: sig,
    );
    blocks.add(block);
    return block;
  }

  /// Validate [block] as the next block and append it. Returns false (and does
  /// not append) if anything is wrong: structure, leader, signature, hash-link,
  /// or an invalid transaction.
  bool appendBlock(AtmBlock block) {
    final height = (head?.height ?? -1) + 1;
    if (block.coinId != coinId) return false;
    if (block.height != height) return false;
    if (block.prevHash != (head?.hash ?? _genesisPrev)) return false;
    if (block.leader != leaderFor(height)) return false;
    if (!NostrCrypto.schnorrVerify(block.hash, block.sig, block.leader)) {
      return false;
    }
    // Counter-signatures, if present, must be from distinct validators.
    for (final cs in block.cosigs) {
      final p = cs['p'], s = cs['sig'];
      if (p == null || s == null || !validators.contains(p)) return false;
      if (!NostrCrypto.schnorrVerify(block.hash, s, p)) return false;
    }
    if (_applyBlock(state, block) == null) return false; // bad tx
    blocks.add(block);
    return true;
  }

  /// Add a counter-signature from another trusted ATM to [block] (quorum proof).
  static AtmBlock cosign(AtmBlock block, String atmPriv) {
    final pub = NostrCrypto.derivePublicKey(atmPriv);
    final sig = NostrCrypto.schnorrSign(block.hash, atmPriv);
    return AtmBlock(
      coinId: block.coinId,
      height: block.height,
      prevHash: block.prevHash,
      txs: block.txs,
      time: block.time,
      leader: block.leader,
      sig: block.sig,
      cosigs: [
        ...block.cosigs,
        {'p': pub, 'sig': sig}
      ],
    );
  }

  // Apply a whole block's txs to a clone; null if any tx is invalid. Sanction
  // windows are anchored to the block's own timestamp.
  AccountState? _applyBlock(AccountState before, AtmBlock block) {
    _applyingBlockTime = block.time;
    final result = _applyTxs(before, block.txs);
    _applyingBlockTime = null;
    return result;
  }

  AccountState? _applyTxs(AccountState before, List<Map<String, dynamic>> txs) {
    final s = before.clone();
    for (final tx in txs) {
      if (!_applyTx(s, tx)) return null;
    }
    return s;
  }

  bool _applyTx(AccountState s, Map<String, dynamic> tx) {
    switch (tx['type']) {
      case 'transfer':
        return _applyTransfer(s, tx);
      case 'redeem':
        return _applyRedeem(s, tx);
      case 'grant':
        return _applyGrant(s, tx);
      case 'fraud':
        return _applyFraud(s, tx);
      default:
        return false;
    }
  }

  bool _applyTransfer(AccountState s, Map<String, dynamic> tx) {
    final from = tx['from'];
    final to = tx['to'];
    final amount = tx['amount'];
    final nonce = tx['nonce'];
    final sig = tx['sig'];
    if (from is! String ||
        to is! String ||
        amount is! int ||
        amount <= 0 ||
        nonce is! String ||
        sig is! String) {
      return false;
    }
    final nonceKey = '$from:$nonce';
    if (s.usedNonces.contains(nonceKey)) return false;
    final body = {
      'type': 'transfer',
      'from': from,
      'to': to,
      'amount': amount,
      'nonce': nonce
    };
    if (!NostrCrypto.schnorrVerify(_txSigningHash(coinId, body), sig, from)) {
      return false;
    }
    if (s.balanceOf(from) < amount) return false;
    s.balances[from] = s.balanceOf(from) - amount;
    s.balances[to] = s.balanceOf(to) + amount;
    s.usedNonces.add(nonceKey);
    return true;
  }

  bool _applyRedeem(AccountState s, Map<String, dynamic> tx) {
    final to = tx['to'];
    final sig = tx['sig'];
    final proof = Proof.fromJson(tx['proof']);
    if (to is! String || sig is! String || proof == null) return false;
    if (proof.keysetId != keyset.keysetId) return false;
    if (s.spentSecrets.contains(proof.secretHex)) return false; // double-spend
    final K = keyset.keyFor(proof.amount);
    if (K == null) return false;
    if (!Bdhke.verifyOffline(proof, K)) return false; // forged token
    // Optional offline-handoff provenance: who gave this token to the redeemer.
    final spendJson = tx['spend'];
    SpendRecord? spend;
    if (spendJson != null) {
      spend = SpendRecord.fromJson(spendJson);
      if (spend == null) return false;
      if (spend.coinId != coinId) return false;
      if (spend.secret != proof.secretHex) return false;
      if (spend.to != to) return false; // record must hand the token to redeemer
      if (!spend.verify()) return false;
    }
    final body = {
      'type': 'redeem',
      'to': to,
      'proof': proof.toJson(),
      'spend': ?spendJson,
    };
    if (!NostrCrypto.schnorrVerify(_txSigningHash(coinId, body), sig, to)) {
      return false;
    }
    s.spentSecrets.add(proof.secretHex);
    s.redeemedTo[proof.secretHex] = to;
    s.redeemedAmount[proof.secretHex] = proof.amount;
    s.balances[to] = s.balanceOf(to) + proof.amount;
    return true;
  }

  /// Apply self-proving double-spend evidence: sanction the culprit per the
  /// ladder, claw back the double-spent value (recording any shortfall as debt),
  /// and reimburse the defrauded victim. Deterministic from on-chain settlement
  /// plus the published sanction policy, so every node derives the same result.
  bool _applyFraud(AccountState s, Map<String, dynamic> tx) {
    final proof = FraudProof.fromJson(tx['proof']);
    if (proof == null) return false;
    if (proof.coinId != coinId) return false;
    if (!proof.verify()) return false; // not a genuine double-spend
    final secret = proof.secret;
    // The disputed token must actually have settled on-chain (real value moved),
    // and we must know which recipient collected it to identify the victim.
    final collectedBy = s.redeemedTo[secret];
    final amount = s.redeemedAmount[secret];
    if (collectedBy == null || amount == null) return false;
    final victim = proof.victimGiven(collectedBy);
    if (victim == null) return false; // proof's recipients don't match the chain
    if (s.adjudicated.contains(secret)) return false; // already handled

    final culprit = proof.culprit;
    final offenses = (s.offenses[culprit] ?? 0) + 1;
    s.offenses[culprit] = offenses;

    // Clawback the double-spent value from the culprit; shortfall becomes debt.
    final avail = s.balanceOf(culprit);
    final taken = avail < amount ? avail : amount;
    if (taken > 0) s.balances[culprit] = avail - taken;
    final priorDebt = s.sanctions[culprit]?.clawback ?? 0;
    final debt = priorDebt + (amount - taken);

    // Reimburse the victim of the invalidated token.
    s.balances[victim] = s.balanceOf(victim) + amount;

    // Escalate: freeze first, suspend on repeat per policy.
    final level = offenses >= sanctionPolicy.suspendAtOffense
        ? SanctionLevel.suspend
        : SanctionLevel.freeze;
    final until = level == SanctionLevel.freeze
        ? _blockTime(s) + sanctionPolicy.freezeSeconds
        : null;
    s.sanctions[culprit] = SanctionState(
      culprit,
      level,
      until: until,
      clawback: debt,
      proofId: secret,
      at: _blockTime(s),
    );
    s.adjudicated.add(secret);
    return true;
  }

  // Timestamp basis for sanction windows: the block currently being applied.
  int _blockTime(AccountState s) => _applyingBlockTime ?? _nowSec();
  int? _applyingBlockTime;

  bool _applyGrant(AccountState s, Map<String, dynamic> tx) {
    final to = tx['to'];
    final amount = tx['amount'];
    final nonce = tx['nonce'];
    final sig = tx['sig'];
    if (to is! String ||
        amount is! int ||
        amount <= 0 ||
        nonce is! String ||
        sig is! String) {
      return false;
    }
    final nonceKey = '$coinId:$nonce';
    if (s.usedNonces.contains(nonceKey)) return false;
    final body = {'type': 'grant', 'to': to, 'amount': amount, 'nonce': nonce};
    // Grants are coinbase: only the administrator (coinId) may authorize them.
    if (!NostrCrypto.schnorrVerify(_txSigningHash(coinId, body), sig, coinId)) {
      return false;
    }
    s.balances[to] = s.balanceOf(to) + amount;
    s.usedNonces.add(nonceKey);
    return true;
  }
}
