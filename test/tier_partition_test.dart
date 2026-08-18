/*
 * The first rule of hosting other people's data (aurora/docs/NOSTR.md, "Abuse"):
 *
 *   A STRANGER CAN NEVER EVICT.
 *
 * The eviction attack is the one that matters. Filling a device with junk is
 * merely rude; the payload is the DELETION it causes — ten thousand generated
 * npubs pushing out the notes you liked and the photos you kept. The answer has
 * to be structural, not a heuristic: stranger bytes compete with STRANGER bytes
 * for a slice of disk the owner sized, and everything the user chose lives
 * outside that slice. Then the attack is not mitigated, it is pointless.
 *
 * These tests are the proof, and they are written as an attacker would: flood,
 * and then assert that the flood deleted only other junk.
 */
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';
import 'package:sqlite3/open.dart';

void _useSystemSqlite() {
  if (!Platform.isLinux) return;
  open.overrideFor(
      OperatingSystem.linux, () => DynamicLibrary.open('libsqlite3.so.0'));
}

const _priv =
    '0001a3f19c8d2b4e6f70a3f19c8d2b4e6f70a3f19c8d2b4e6f701b2c00000001';
late String _pub;

const _quota = HostQuota(
  ceilingBytes: 10000,
  strangerSliceBytes: 1000,
  strangerNotesPerMonth: 50,
  strangerRetentionMs: 7 * 24 * 3600 * 1000,
);

StoredItem _item(String id, Tier tier, int bytes,
        {int at = 0, bool media = false}) =>
    StoredItem(id, tier, bytes, at, media);

void main() {
  setUpAll(() {
    _useSystemSqlite();
    _pub = NostrCrypto.derivePublicKey(_priv);
  });

  test('a flood of stranger junk evicts ONLY stranger junk', () {
    final items = <StoredItem>[
      _item('mine', Tier.self, 3000, at: 1),
      _item('kept-note', Tier.followed, 3000, at: 2),
      _item('kept-photo', Tier.followed, 3000, at: 3, media: true),
      // The attack: 20 npubs' worth of junk, far past the stranger slice.
      for (var i = 0; i < 20; i++) _item('junk$i', Tier.stranger, 500, at: 10 + i),
    ];

    final dropped = planEviction(items, _quota, nowMs: 100);

    expect(dropped, isNotEmpty);
    expect(dropped.every((id) => id.startsWith('junk')), isTrue,
        reason: 'the flood may only ever delete the flood');
    expect(dropped, isNot(contains('mine')));
    expect(dropped, isNot(contains('kept-note')));
    expect(dropped, isNot(contains('kept-photo')));

    // And the strangers that survive fit the slice the owner sized.
    final survivingStranger = items
        .where((i) => i.tier == Tier.stranger && !dropped.contains(i.id))
        .fold<int>(0, (s, i) => s + i.bytes);
    expect(survivingStranger, lessThanOrEqualTo(_quota.strangerSliceBytes));
  });

  test('followed media is only ever touched when OUR OWN data fills the node',
      () {
    // No strangers at all: the node is over its ceiling because of what the
    // user themselves chose to keep. Only then may followed media go.
    final items = <StoredItem>[
      _item('mine', Tier.self, 6000, at: 1),
      _item('followed-text', Tier.followed, 3000, at: 2),
      _item('followed-photo', Tier.followed, 4000, at: 3, media: true),
    ];
    final dropped = planEviction(items, _quota, nowMs: 100);
    expect(dropped, ['followed-photo']);
    expect(dropped, isNot(contains('followed-text')),
        reason: 'a followed persons WORDS are never dropped');
    expect(dropped, isNot(contains('mine')));
  });

  test('admission refuses the flood at the door, not after it lands', () {
    final full = admit(
      Tier.stranger,
      500,
      isMedia: false,
      totalHostedBytes: 5000,
      strangerHostedBytes: 1000, // slice already full
      strangerNotesThisMonth: 0,
      q: _quota,
    );
    expect(full.ok, isFalse);
    expect(full.reason, contains('stranger storage limit'));

    // Our own content is never refused, whatever the state of the disk.
    expect(
      admit(Tier.self, 9999,
              isMedia: false,
              totalHostedBytes: 9999,
              strangerHostedBytes: 1000,
              strangerNotesThisMonth: 999,
              q: _quota)
          .ok,
      isTrue,
    );
  });

  test('the monthly note cap stops a slow drip as well as a flood', () {
    final d = admit(
      Tier.stranger,
      10,
      isMedia: false,
      totalHostedBytes: 0,
      strangerHostedBytes: 0,
      strangerNotesThisMonth: 50,
      q: _quota,
    );
    expect(d.ok, isFalse);
    expect(d.reason, contains('monthly note limit'));
  });

  test('the retention sweep deletes strangers, and cannot reach what I kept',
      () {
    final store = RelayEventStore.open(':memory:');
    addTearDown(store.close);

    NostrEvent note(String content, int at) {
      final e = NostrEvent(
        pubkey: _pub,
        createdAt: at,
        kind: NostrEventKind.textNote,
        tags: const [],
        content: content,
      );
      e.sign(_priv);
      return e;
    }

    final old = DateTime.now().millisecondsSinceEpoch ~/ 1000 - 999999;
    final junk = note('junk', old);
    final kept = note('the note I liked', old);
    final mine = note('my own post', old);

    // All three are equally ancient. Only the tier differs.
    store.put(junk, tier: 2, receivedAtMs: 0);
    store.put(kept, tier: 2, receivedAtMs: 0);
    store.put(mine, tier: 0, receivedAtMs: 0);
    // The user liked one of them: it is theirs now.
    expect(store.pin(kept.id!), isTrue);

    final removed = store.pruneHosted(strangerMaxAge: const Duration(days: 7));

    expect(removed, 1, reason: 'only the stranger note aged out');
    expect(store.query(NostrFilter(ids: [junk.id!])), isEmpty);
    expect(store.query(NostrFilter(ids: [kept.id!])), hasLength(1),
        reason: 'touching it took it out of the strangers slice for good');
    expect(store.query(NostrFilter(ids: [mine.id!])), hasLength(1));
  });
}
