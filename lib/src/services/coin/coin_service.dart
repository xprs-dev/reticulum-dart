/*
 * coin_service — high-level facades the UI (a wapp) and node code call, tying
 * together the keyset, wallet, authority log, ATM chain, postage and faucet.
 * Self-contained: this does NOT touch shared host files; a wapp would call these
 * methods and render the results.
 *
 *  - CoinService: the wallet/user side for one coin on this device — balances,
 *    online transfers, offline bearer hand-off (send/receive), and postage.
 *  - CoinAdmin: the administrator side — emits the signed, incrementally indexed
 *    authority decisions (define/issue/grant/faucet/ATM/sanction/lift), keeping
 *    the sequence + prev-hash chain correct.
 *
 * Pure/headless except CoinService, which uses CoinWallet (sqlite, native only).
 */
import '../../util/nostr_crypto.dart';
import '../../util/nostr_event.dart';
import 'atm_chain.dart';
import 'authority_log.dart';
import 'bearer_token.dart';
import 'coin_keyset.dart';
import 'fraud.dart';
import 'postage.dart';
import 'wallet.dart';

/// Result of selecting + reserving wallet proofs for an outgoing payment.
class _Picked {
  final List<Proof> proofs;
  const _Picked(this.proofs);
  int get total => proofs.fold(0, (a, p) => a + p.amount);
}

/// The wallet/user side of one coin on this device.
class CoinService {
  final String coinId;
  final String myPriv;
  final String myPub;
  final CoinKeyset keyset;
  final CoinWallet wallet;

  CoinService({
    required this.coinId,
    required this.myPriv,
    required this.keyset,
    required this.wallet,
  }) : myPub = NostrCrypto.derivePublicKey(myPriv);

  /// Spendable bearer holdings on this device.
  int walletBalance() => wallet.balance(coinId);

  /// On-chain account balance, given the chain's current [state].
  int accountBalance(AccountState state) => state.balanceOf(myPub);

  /// Store bearer proofs (e.g. freshly minted to us) into the wallet, verifying
  /// each is authentic against the published keyset. Returns the amount stored.
  int storeProofs(Iterable<Proof> proofs) {
    var total = 0;
    for (final p in proofs) {
      if (!_authentic(p)) continue;
      if (wallet.add(coinId, p)) total += p.amount;
    }
    return total;
  }

  // ── online path (preferred) ────────────────────────────────────────────────

  /// Build a signed account transfer to [toPub] (settles on the ATM chain).
  Map<String, dynamic> buildTransfer(String toPub, int amount, String nonce) =>
      buildTransferTx(coinId, myPriv, toPub, amount, nonce);

  /// Redeem held bearer proofs into our on-chain account (bearer -> account).
  /// Returns the redeem txs (hand to an ATM); marks the proofs spent locally.
  List<Map<String, dynamic>> redeemToAccount() {
    final txs = <Map<String, dynamic>>[];
    for (final p in wallet.unspent(coinId)) {
      txs.add(buildRedeemTx(coinId, myPriv, p));
      wallet.markSpent(p.secretHex);
    }
    return txs;
  }

  // ── offline path (emergency / no ATM reachable) ─────────────────────────────

  /// Hand bearer value worth at least [amount] to [toPub] fully offline. Returns
  /// the token plus a signed spend record per proof (provenance, so a later
  /// double-spend is attributable to us). Reserves the proofs locally. Returns
  /// null if holdings are insufficient. Note: no change-making yet — the picked
  /// set may exceed [amount] (swap-for-change is a later mint feature).
  OfflineHandoff? sendOffline(String toPub, int amount) {
    final picked = _pick(amount);
    if (picked == null) return null;
    final records = <SpendRecord>[];
    for (final p in picked.proofs) {
      records.add(SpendRecord.build(coinId, myPriv, p.secretHex, toPub));
      wallet.markSpent(p.secretHex);
    }
    return OfflineHandoff(BearerToken(coinId, picked.proofs), records);
  }

  /// Receive an offline [handoff] addressed to us: verify each proof is authentic
  /// and each record hands it to us, then store. Returns the amount accepted.
  int receiveOffline(OfflineHandoff handoff) {
    final bySecret = {for (final r in handoff.records) r.secret: r};
    var total = 0;
    for (final p in handoff.token.proofs) {
      final rec = bySecret[p.secretHex];
      if (rec == null) continue;
      if (rec.coinId != coinId || rec.to != myPub) continue;
      if (!rec.verify()) continue;
      if (!_authentic(p)) continue;
      if (wallet.add(coinId, p)) total += p.amount;
    }
    return total;
  }

  // ── postage ────────────────────────────────────────────────────────────────

  /// Build postage worth at least [amount] payable to [relayPub]; reserves the
  /// proofs. Returns one Postage per proof, or null if holdings are short.
  List<Postage>? buildPostage(String relayPub, int amount) {
    final picked = _pick(amount);
    if (picked == null) return null;
    final out = <Postage>[];
    for (final p in picked.proofs) {
      out.add(Postage.build(coinId, myPriv, p, relayPub));
      wallet.markSpent(p.secretHex);
    }
    return out;
  }

  bool _authentic(Proof p) {
    if (p.keysetId != keyset.keysetId) return false;
    final k = keyset.keyFor(p.amount);
    return k != null && Bdhke.verifyOffline(p, k);
  }

  _Picked? _pick(int amount) {
    final proofs = wallet.selectForAmount(coinId, amount);
    if (proofs.isEmpty) return null;
    return _Picked(proofs);
  }
}

/// A signed, offline bearer transfer: the token plus a spend record per proof.
class OfflineHandoff {
  final BearerToken token;
  final List<SpendRecord> records;
  const OfflineHandoff(this.token, this.records);

  int get amount => token.amount;

  Map<String, dynamic> toJson() => {
        'token': token.encode(),
        'records': [for (final r in records) r.toJson()],
      };

  static OfflineHandoff? fromJson(Object? o) {
    if (o is! Map) return null;
    final token = o['token'] is String ? BearerToken.decode(o['token'] as String) : null;
    final recs = o['records'];
    if (token == null || recs is! List) return null;
    final records = <SpendRecord>[];
    for (final e in recs) {
      final r = SpendRecord.fromJson(e);
      if (r == null) return null;
      records.add(r);
    }
    return OfflineHandoff(token, records);
  }
}

/// The administrator side: emits the signed authority decisions for a coin,
/// keeping the sequence index and prev-hash chain correct. Resume from an
/// existing [CoinPolicy] (its lastSeq/headId) or start fresh at genesis.
class CoinAdmin {
  final String coinId;
  final String adminPriv;
  int _seq;
  String? _prevId;

  CoinAdmin(this.adminPriv, {CoinPolicy? resumeFrom})
      : coinId = NostrCrypto.derivePublicKey(adminPriv),
        _seq = (resumeFrom?.lastSeq ?? -1) + 1,
        _prevId = resumeFrom?.headId;

  int get nextSeq => _seq;
  String? get headId => _prevId;

  NostrEvent _emit(Map<String, dynamic> op, {int? createdAt}) {
    final e = buildAuthority(adminPriv, coinId, _seq, op,
        prevId: _prevId, createdAt: createdAt);
    _seq++;
    _prevId = e.id;
    return e;
  }

  NostrEvent define(
          {required String name,
          required String symbol,
          int decimals = 0,
          required CoinKeyset keyset,
          int? createdAt}) =>
      _emit(
          opDefine(
              name: name, symbol: symbol, decimals: decimals, keyset: keyset),
          createdAt: createdAt);

  NostrEvent issue(int amount, {int? createdAt}) =>
      _emit(opIssue(amount), createdAt: createdAt);

  NostrEvent grant(String toPub, int amount, {String? reason, int? createdAt}) =>
      _emit(opGrant(toPub, amount, reason: reason), createdAt: createdAt);

  NostrEvent setFaucet(Map<String, dynamic> rules, {int? createdAt}) =>
      _emit(opSetFaucet(rules), createdAt: createdAt);

  NostrEvent addAtm(String pub, {int? createdAt}) =>
      _emit(opAddAtm(pub), createdAt: createdAt);

  NostrEvent revokeAtm(String pub, {int? createdAt}) =>
      _emit(opRevokeAtm(pub), createdAt: createdAt);

  NostrEvent sanction(String pub, String level,
          {int? until, int? clawback, String? proofId, int? createdAt}) =>
      _emit(
          opSanction(pub, level,
              until: until, clawback: clawback, proofId: proofId),
          createdAt: createdAt);

  NostrEvent lift(String pub, {int? createdAt}) =>
      _emit(opLift(pub), createdAt: createdAt);

  NostrEvent setPolicy(Map<String, dynamic> policy, {int? createdAt}) =>
      _emit(opSetPolicy(policy), createdAt: createdAt);
}
