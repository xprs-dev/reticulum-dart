/*
 * The Archiver's contract with its owner (aurora/docs/NOSTR.md).
 *
 * Two things must be true, and a test is the only way to keep them true:
 *   - a device that never volunteered holds nothing for anybody (silence is not
 *     consent), and
 *   - a quota is a CEILING, not a target — full is full, and no clever reason
 *     gets past it.
 */
import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/services/social/archiver_policy.dart';
import 'package:reticulum/src/services/social/retention_tier.dart';

void main() {
  const mb = 1024 * 1024;

  const volunteer = ArchiverPolicy(
    quotaBytes: 100 * mb,
    keepFollowedAuthors: true,
    topics: {'offgrid'},
    acceptFrom: {ArrivedOver.lan, ArrivedOver.radio},
    mirrorSmallDevices: true,
  );

  ArchiveVerdict ask({
    ArchiverPolicy policy = volunteer,
    Tier tier = Tier.stranger,
    int bytes = mb,
    int used = 0,
    ArrivedOver via = ArrivedOver.internet,
    Iterable<String> topics = const [],
    bool followed = false,
  }) =>
      admitToArchive(
        policy: policy,
        tier: tier,
        bytes: bytes,
        usedBytes: used,
        via: via,
        topics: topics,
        authorFollowed: followed,
      );

  test('a device that never volunteered holds nothing — silence is not consent',
      () {
    final v = ask(policy: ArchiverPolicy.none);
    expect(v.accept, isFalse);
    expect(v.reason, 'not an archiver');
  });

  test('the quota is a ceiling, not a target', () {
    // A followed author, so only the quota is in play here.
    expect(ask(tier: Tier.followed, used: 99 * mb, bytes: 2 * mb).accept,
        isFalse);
    expect(ask(tier: Tier.followed, used: 99 * mb, bytes: 1 * mb).accept,
        isTrue);
  });

  test('a full archive refuses even a followed author — full is full', () {
    final v = ask(tier: Tier.followed, used: 100 * mb, bytes: 1);
    expect(v.accept, isFalse);
    expect(v.reason, 'archive full');
  });

  test('the peer with nowhere else to go gets in on the strength of the link',
      () {
    // A stranger over LoRa: no route to anywhere, and its data dies if we say
    // no. That is the entire reason a village-hall box runs this role.
    expect(ask(via: ArrivedOver.radio).accept, isTrue);
    expect(ask(via: ArrivedOver.lan).accept, isTrue);

    // …but only over the links the owner actually offered.
    expect(ask(via: ArrivedOver.bluetooth).accept, isFalse,
        reason: 'not in acceptFrom: the owner said LAN and radio, not BLE');
  });

  test('a stranger off the internet is not our problem', () {
    final v = ask(via: ArrivedOver.internet);
    expect(v.accept, isFalse,
        reason: 'an archiver is redundancy, not an open dumpster');
  });

  test('redundancy for the people the owner already cares about', () {
    expect(ask(tier: Tier.followed).accept, isTrue);
    expect(ask(followed: true).accept, isTrue);
  });

  test('a topic the owner volunteered for', () {
    expect(ask(topics: ['offgrid']).accept, isTrue);
    expect(ask(topics: ['crypto-casino']).accept, isFalse);
  });

  test("the owner's own data is not governed by the archive quota", () {
    final v = ask(tier: Tier.self, used: 100 * mb, bytes: 50 * mb);
    expect(v.accept, isTrue,
        reason: 'the quota is what we hold for OTHERS; our own is ours');
  });

  test('a refusal always says why — a silent node teaches its neighbours '
      'nothing', () {
    for (final v in [
      ask(policy: ArchiverPolicy.none),
      ask(used: 100 * mb),
      ask(via: ArrivedOver.internet),
    ]) {
      expect(v.accept, isFalse);
      expect(v.reason, isNotNull);
      expect(v.reason, isNotEmpty);
    }
  });
}
