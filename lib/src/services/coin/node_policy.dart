/*
 * node_policy — the effective view a node enforces, merging the two sanction
 * sources into one answer to "may this npub transact right now?".
 *
 *  - Authority-log sanctions (CoinPolicy.sanctions): explicit administrator
 *    decisions. An admin `lift` removes these.
 *  - Chain-derived sanctions (AccountState.sanctions): applied automatically by
 *    ATMs from on-chain double-spend fraud proofs.
 *
 * A node bars an npub if EITHER source is in force. The administrator stays in
 * control: an admin `lift` whose time is at/after the offense overrides a
 * chain-derived sanction too (CoinPolicy.lifts carries the lift time). A new
 * offense after a lift re-bars, because its sanction timestamp is later.
 *
 * Pure/headless: authority_log + atm_chain.
 */
import 'atm_chain.dart' show AccountState;
import 'authority_log.dart';

class BarStatus {
  final bool barred;
  final String? source; // 'authority' | 'chain' | null
  final String? level; // freeze | suspend
  final int debt; // outstanding clawback owed
  const BarStatus(this.barred, {this.source, this.level, this.debt = 0});
}

class NodePolicy {
  /// Is [pub] barred from transacting at [ts], considering both sources?
  static bool isBarred(String pub, int ts,
          {required CoinPolicy authority, AccountState? chain}) =>
      status(pub, ts, authority: authority, chain: chain).barred;

  /// The merged sanction status for [pub] at [ts].
  static BarStatus status(String pub, int ts,
      {required CoinPolicy authority, AccountState? chain}) {
    // Authority-log sanctions are already cleared by an admin lift, so presence
    // means in force.
    final auth = authority.sanctions[pub];
    if (auth != null && auth.activeAt(ts)) {
      return BarStatus(true,
          source: 'authority', level: auth.level, debt: auth.clawback);
    }

    // Chain-derived sanction, unless an admin lift at/after the offense overrides.
    final cs = chain?.sanctions[pub];
    if (cs != null && cs.activeAt(ts)) {
      final liftedAt = authority.lifts[pub];
      final overridden = liftedAt != null && liftedAt >= cs.at;
      if (!overridden) {
        return BarStatus(true,
            source: 'chain', level: cs.level, debt: cs.clawback);
      }
    }
    return const BarStatus(false);
  }

  /// Outstanding clawback debt for [pub] from the chain ledger.
  static int debtOf(String pub, AccountState chain) => chain.debtOf(pub);
}
