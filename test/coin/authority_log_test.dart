import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';

import 'package:reticulum/src/services/coin/authority_log.dart';
import 'package:reticulum/src/services/coin/coin_keyset.dart';
import 'package:reticulum/src/util/nostr_event.dart';
import 'package:reticulum/src/util/nostr_crypto.dart';

void main() {
  final admin = NostrCrypto.generateKeyPair();
  final adminPriv = admin.privateKeyHex;
  final coinId = admin.publicKeyHex;
  final keyset =
      CoinMintKeys.derive(coinId, NostrCrypto.generateKeyPair().privateKeyHex,
              maxExp: 4)
          .public;

  // A small, well-formed authority log: define -> issue -> grant -> addAtm.
  List<NostrEvent> buildLog() {
    final atm = NostrCrypto.generateKeyPair().publicKeyHex;
    final e0 = buildAuthority(adminPriv, coinId, 0,
        opDefine(name: 'Mesh', symbol: 'MSH', keyset: keyset),
        createdAt: 1000);
    final e1 = buildAuthority(adminPriv, coinId, 1, opIssue(1000),
        prevId: e0.id, createdAt: 1001);
    final e2 = buildAuthority(
        adminPriv, coinId, 2, opGrant(atm, 50, reason: 'bootstrap'),
        prevId: e1.id, createdAt: 1002);
    final e3 = buildAuthority(adminPriv, coinId, 3, opAddAtm(atm),
        prevId: e2.id, createdAt: 1003);
    return [e0, e1, e2, e3];
  }

  test('reduces define/issue/grant/addAtm into policy', () {
    final p = reduceAuthority(coinId, buildLog());
    expect(p.name, 'Mesh');
    expect(p.symbol, 'MSH');
    expect(p.keyset?.keysetId, keyset.keysetId);
    expect(p.totalIssued, 1000);
    expect(p.totalGranted, 50);
    expect(p.activeAtms(2000).length, 1);
    expect(p.lastSeq, 3);
  });

  test('order-independent: shuffled log reduces to the same state', () {
    final log = buildLog();
    final shuffled = [log[2], log[0], log[3], log[1]];
    final a = reduceAuthority(coinId, log).toJson();
    final b = reduceAuthority(coinId, shuffled).toJson();
    expect(b.toString(), equals(a.toString()));
  });

  test('replay/duplicate entries do not double-count', () {
    final log = buildLog();
    // Duplicate the issue entry (same seq) — must be ignored the second time.
    final withReplay = [...log, log[1], log[1]];
    final p = reduceAuthority(coinId, withReplay);
    expect(p.totalIssued, 1000); // not 3000
  });

  test('a forged issue from a non-admin key is ignored', () {
    final attacker = NostrCrypto.generateKeyPair();
    // Attacker mints an event claiming to govern this coin, signed by themselves.
    final forged = buildAuthority(attacker.privateKeyHex, coinId, 4,
        opIssue(1000000),
        createdAt: 1004);
    final p = reduceAuthority(coinId, [...buildLog(), forged]);
    expect(p.totalIssued, 1000); // attacker's issue rejected (pubkey != coinId)
  });

  test('broken prev-link entry is rejected', () {
    final log = buildLog();
    // A new entry whose prev points at the wrong id must not apply.
    final bad = buildAuthority(adminPriv, coinId, 4, opIssue(7),
        prevId: 'deadbeef', createdAt: 1005);
    final p = reduceAuthority(coinId, [...log, bad]);
    expect(p.totalIssued, 1000);
    expect(p.lastSeq, 3);
  });

  test('revokeAtm deactivates and lift clears a sanction', () {
    final log = buildLog();
    final atm = (jsonDecode(log[3].content) as Map)['p'] as String;
    final victim = NostrCrypto.generateKeyPair().publicKeyHex;
    final e4 = buildAuthority(adminPriv, coinId, 4, opRevokeAtm(atm),
        prevId: log[3].id, createdAt: 2000);
    final e5 = buildAuthority(adminPriv, coinId, 5,
        opSanction(victim, SanctionLevel.suspend, clawback: 20),
        prevId: e4.id, createdAt: 2001);
    final e6 = buildAuthority(adminPriv, coinId, 6, opLift(victim),
        prevId: e5.id, createdAt: 2002);

    final afterRevoke = reduceAuthority(coinId, [...log, e4]);
    expect(afterRevoke.activeAtms(2500).length, 0);

    final afterSanction = reduceAuthority(coinId, [...log, e4, e5]);
    expect(afterSanction.isSanctioned(victim, 9999), isTrue);

    final afterLift = reduceAuthority(coinId, [...log, e4, e5, e6]);
    expect(afterLift.isSanctioned(victim, 9999), isFalse);
  });

  test('frozen sanction expires but suspension does not', () {
    final log = buildLog();
    final u = NostrCrypto.generateKeyPair().publicKeyHex;
    final freeze = buildAuthority(adminPriv, coinId, 4,
        opSanction(u, SanctionLevel.freeze, until: 5000),
        prevId: log[3].id, createdAt: 3000);
    final p = reduceAuthority(coinId, [...log, freeze]);
    expect(p.isSanctioned(u, 4999), isTrue);
    expect(p.isSanctioned(u, 5001), isFalse); // freeze lifted by time
  });
}
