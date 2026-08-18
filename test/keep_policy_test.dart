/*
 * The touch rule (aurora/docs/NOSTR.md, "the bridge"): interacting with an event
 * keeps THE EVENT — its author, the thread above it, its media — and not merely
 * the reaction to it. That is what lets a note first read on a public internet
 * relay survive the death of that relay, on a device with no internet at all.
 *
 * The property that matters most here is the one a hostile peer would attack:
 * a keep can only ever PROMOTE. Nothing arriving off the wire may push a note
 * the user chose to keep back down into the evictable stranger slice.
 */
import 'dart:ffi';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/reticulum.dart';
import 'package:reticulum/src/services/social/keep_policy.dart';
import 'package:sqlite3/open.dart';

void _useSystemSqlite() {
  if (!Platform.isLinux) return;
  open.overrideFor(
      OperatingSystem.linux, () => DynamicLibrary.open('libsqlite3.so.0'));
}

const _authorPriv =
    '0001a3f19c8d2b4e6f70a3f19c8d2b4e6f70a3f19c8d2b4e6f701b2c00000001';
const _minePriv =
    '0002b4f29d8e3c5f7081b4f29d8e3c5f7081b4f29d8e3c5f7812c3d00000002';

late String _authorPub;
late String _minePub;

NostrEvent _signed(
  String priv,
  String pub, {
  int kind = NostrEventKind.textNote,
  String content = '',
  List<List<String>> tags = const [],
}) {
  final ev = NostrEvent(
    pubkey: pub,
    createdAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
    kind: kind,
    tags: tags,
    content: content,
  );
  ev.sign(priv);
  return ev;
}

void main() {
  late RelayEventStore store;

  setUpAll(() {
    _useSystemSqlite();
    _authorPub = NostrCrypto.derivePublicKey(_authorPriv);
    _minePub = NostrCrypto.derivePublicKey(_minePriv);
  });

  setUp(() => store = RelayEventStore.open(':memory:'));
  tearDown(() => store.close());

  test('a like keeps the note it liked, not just the reaction', () {
    final target =
        _signed(_authorPriv, _authorPub, content: 'a post worth keeping');
    expect(store.put(target, tier: 2), isTrue);
    expect(store.tierOfId(target.id!), 2, reason: 'it arrived as a stranger');

    final plan = planKeep(
        touch: Touch.react, targetId: target.id!, target: target, store: store);
    expect(plan.pinIds, contains(target.id));
    expect(applyKeep(plan, store), 1);

    expect(store.tierOfId(target.id!), 0,
        reason: 'the thing I liked is mine to keep now');
  });

  test('a keep only ever promotes — a re-send cannot demote what I kept', () {
    final target = _signed(_authorPriv, _authorPub, content: 'kept');
    store.put(target, tier: 2);
    expect(store.pin(target.id!), isTrue);

    // The same event arrives again off the wire, offered as a stranger's.
    store.put(target, tier: 2);
    expect(store.pin(target.id!, tier: 2), isFalse);
    expect(store.tierOfId(target.id!), 0,
        reason: 'nothing may push a kept note back into the evictable slice');
  });

  test('a reply keeps the thread above it, and names the parents we lack', () {
    final root = _signed(_authorPriv, _authorPub, content: 'the root');
    final mid = _signed(_authorPriv, _authorPub, content: 'the middle', tags: [
      ['e', root.id!]
    ]);
    // We hold `mid` but not `root` — the usual case for a note off a firehose.
    store.put(mid, tier: 2);

    final plan = planKeep(
        touch: Touch.reply, targetId: mid.id!, target: mid, store: store);

    expect(plan.pinIds, containsAll([mid.id, root.id]));
    expect(plan.fetchIds, [root.id],
        reason: 'a reply with no context is worthless in ten years');
    expect(plan.fetchProfiles, contains(_authorPub),
        reason: 'a note whose author is anonymous later is half a memory');
  });

  test('thread walking is bounded — a crafted deep chain cannot hang us', () {
    var prev = _signed(_authorPriv, _authorPub, content: 'n0');
    store.put(prev, tier: 2);
    for (var i = 1; i < 40; i++) {
      final e = _signed(_authorPriv, _authorPub, content: 'n$i', tags: [
        ['e', prev.id!]
      ]);
      store.put(e, tier: 2);
      prev = e;
    }
    final plan = planKeep(
        touch: Touch.reply, targetId: prev.id!, target: prev, store: store);
    expect(plan.pinIds.length, lessThanOrEqualTo(kMaxThreadDepth + 1));
  });

  test('an unheld target is fetched first, and the plan says exactly that', () {
    final plan = planKeep(
        touch: Touch.bookmark, targetId: 'f' * 64, target: null, store: store);
    expect(plan.fetchIds, ['f' * 64]);
    expect(plan.pinIds, isEmpty, reason: 'cannot pin what we do not hold');
  });

  test('media comes too, while the internet that holds it is still there', () {
    final sha = 'a' * 64;
    final target = _signed(_authorPriv, _authorPub,
        content: 'look https://blossom.primal.net/$sha.jpg and '
            'file:${'A' * 43}.png');
    store.put(target, tier: 2);

    final plan = planKeep(
        touch: Touch.react, targetId: target.id!, target: target, store: store);
    expect(plan.fetchMedia, hasLength(2));
    expect(plan.fetchMedia.any((m) => m.contains(sha)), isTrue);
  });

  test('media refs: blossom urls, inline images, file: tokens — and bounded',
      () {
    final refs = mediaRefsIn(
      'https://x.test/${'b' * 64} https://y.test/pic.jpeg?x=1 '
      'file:${'C' * 43}.mp4 https://z.test/page.html',
    );
    expect(refs, hasLength(3),
        reason: 'the html page is not media; the other three are');
    expect(mediaRefsIn(List.generate(20, (i) => 'https://x/$i.png').join(' ')),
        hasLength(kMaxMediaPerNote));
  });

  test('applying the same keep twice changes nothing', () {
    final target = _signed(_authorPriv, _authorPub, content: 'twice');
    store.put(target, tier: 2);
    final plan = planKeep(
        touch: Touch.zap, targetId: target.id!, target: target, store: store);
    expect(applyKeep(plan, store), 1);
    expect(applyKeep(plan, store), 0);
    expect(store.tierOfId(target.id!), 0);
  });

  test('missingIds reports exactly what we still have to go and get', () {
    final have = _signed(_minePriv, _minePub, content: 'mine');
    store.put(have, tier: 0);
    expect(store.missingIds([have.id!, 'd' * 64]), ['d' * 64]);
  });

  test('targetOf takes the LAST e tag — NIP-10: the note I acted on', () {
    final e = _signed(_minePriv, _minePub,
        kind: NostrEventKind.reaction,
        content: '+',
        tags: [
          ['e', 'r' * 64],
          ['e', 'p' * 64],
        ]);
    expect(targetOf(e), 'p' * 64);
  });
}
