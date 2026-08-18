/*
 * fraud — offline-handoff spend records and self-proving double-spend evidence.
 *
 * When a bearer token is handed to someone OFFLINE, the giver signs a
 * SpendRecord binding the token's secret to exactly one recipient. If the giver
 * cheats and hands the same token to two recipients, the two records — same
 * secret, same `from`, different `to`, both validly signed by `from` — are an
 * irrefutable FraudProof attributing the double-spend to `from`. Anyone can
 * verify it with no trust, which is what makes the public sanction fair.
 *
 * The ATM chain consumes these: a redeem carries the spend record (provenance),
 * and a `fraud` tx carries the two conflicting records to trigger the sanction
 * ladder deterministically (see atm_chain.dart).
 *
 * Pure/headless: nostr_crypto only.
 */
import '../../util/nostr_crypto.dart';

/// A signed, offline transfer of a bearer token from one holder to one recipient.
class SpendRecord {
  final String coinId;
  final String secret; // the bearer token's secret (its unique id)
  final String from; // giver pubkey (x-only hex)
  final String to; // recipient pubkey
  final String sig; // schnorr sig by `from`

  const SpendRecord(this.coinId, this.secret, this.from, this.to, this.sig);

  static String signingHash(String coinId, String secret, String from, String to) =>
      NostrCrypto.sha256Hash('spend|$coinId|$secret|$from|$to');

  /// Build a record handing the token [secret] from [fromPriv]'s owner to [to].
  factory SpendRecord.build(
      String coinId, String fromPriv, String secret, String to) {
    final from = NostrCrypto.derivePublicKey(fromPriv);
    final sig =
        NostrCrypto.schnorrSign(signingHash(coinId, secret, from, to), fromPriv);
    return SpendRecord(coinId, secret, from, to, sig);
  }

  bool verify() => NostrCrypto.schnorrVerify(
      signingHash(coinId, secret, from, to), sig, from);

  Map<String, dynamic> toJson() =>
      {'coinId': coinId, 'secret': secret, 'from': from, 'to': to, 'sig': sig};

  static SpendRecord? fromJson(Object? o) {
    if (o is! Map) return null;
    final coinId = o['coinId'];
    final secret = o['secret'];
    final from = o['from'];
    final to = o['to'];
    final sig = o['sig'];
    if (coinId is! String ||
        secret is! String ||
        from is! String ||
        to is! String ||
        sig is! String) {
      return null;
    }
    return SpendRecord(coinId, secret, from, to, sig);
  }
}

/// Two conflicting spend records proving [culprit] double-spent one token.
class FraudProof {
  final SpendRecord a;
  final SpendRecord b;

  const FraudProof(this.a, this.b);

  /// Valid iff both records verify, share a coin + secret + giver, but name
  /// different recipients (i.e. the giver spent the same token twice).
  bool verify() {
    if (!a.verify() || !b.verify()) return false;
    if (a.coinId != b.coinId) return false;
    if (a.secret != b.secret) return false;
    if (a.from != b.from) return false;
    if (a.to == b.to) return false;
    return true;
  }

  String get coinId => a.coinId;
  String get secret => a.secret;
  String get culprit => a.from;

  /// Given which recipient actually collected the value on-chain, the other is
  /// the defrauded victim. Returns null if [redeemedTo] is neither recipient.
  String? victimGiven(String redeemedTo) {
    if (a.to == redeemedTo) return b.to;
    if (b.to == redeemedTo) return a.to;
    return null;
  }

  Map<String, dynamic> toJson() => {'a': a.toJson(), 'b': b.toJson()};

  static FraudProof? fromJson(Object? o) {
    if (o is! Map) return null;
    final a = SpendRecord.fromJson(o['a']);
    final b = SpendRecord.fromJson(o['b']);
    if (a == null || b == null) return null;
    return FraudProof(a, b);
  }
}

/// Sanction-ladder parameters; read from the coin's published policy
/// (CoinPolicy.sanctionPolicy) with these defaults.
class SanctionPolicy {
  final int freezeSeconds; // freeze duration for a first offense
  final int suspendAtOffense; // offense count at which suspension kicks in

  const SanctionPolicy(
      {this.freezeSeconds = 7 * 24 * 3600, this.suspendAtOffense = 2});

  static SanctionPolicy fromMap(Map<String, dynamic> m) => SanctionPolicy(
        freezeSeconds:
            m['freezeSeconds'] is int ? m['freezeSeconds'] as int : 7 * 24 * 3600,
        suspendAtOffense:
            m['suspendAtOffense'] is int ? m['suspendAtOffense'] as int : 2,
      );

  Map<String, dynamic> toMap() =>
      {'freezeSeconds': freezeSeconds, 'suspendAtOffense': suspendAtOffense};
}
