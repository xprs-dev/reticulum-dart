/*
 * Statistics and cleanup, not a list of blobs (aurora/docs/NOSTR.md).
 *
 * An archive holds hundreds of thousands of files. Scrolling that is not a
 * feature — a person cannot learn anything from it and cannot act on it. What
 * they need is where the space went, and how to get it back, and a preview of
 * what a cleanup is about to delete BEFORE it deletes it: a cleanup tool that
 * cannot tell you what it will remove is not a tool, it is a gamble.
 *
 * The rule the sweeps must never break: what the owner asked to KEEP (pinned)
 * and the owner's OWN media are not the archive's to delete, however full it is.
 */
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:reticulum/src/util/media_archive.dart';
import 'package:sqlite3/open.dart';

Uint8List _blob(int seed, int size) =>
    Uint8List.fromList(List.filled(size, seed & 0xff));

void main() {
  setUpAll(() {
    if (Platform.isLinux) {
      open.overrideFor(
          OperatingSystem.linux, () => DynamicLibrary.open('libsqlite3.so.0'));
    }
  });

  late Directory dir;
  late MediaArchive archive;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('sweep');
    archive = MediaArchive.forDirectory(dir.path);
  });

  tearDown(() {
    archive.close();
    dir.deleteSync(recursive: true);
  });

  const day = 24 * 3600 * 1000;

  void seed({int? nowMs}) {
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;
    // Two strangers, one old and one new.
    archive.putHosted(_blob(1, 4000), 'jpg',
        originPubHex: 'a' * 64, tier: 2, receivedAtMs: now - 40 * day);
    archive.putHosted(_blob(2, 2000), 'jpg',
        originPubHex: 'b' * 64, tier: 2, receivedAtMs: now - day);
    // A followed author.
    archive.putHosted(_blob(3, 1000), 'jpg',
        originPubHex: 'c' * 64, tier: 1, receivedAtMs: now - 10 * day);
    // Something the user asked to KEEP.
    archive.putHosted(_blob(4, 500), 'jpg',
        originPubHex: 'd' * 64, tier: 0, pin: true, receivedAtMs: now - day);
  }

  test('stats say where the space went — not which files are in there', () {
    seed();
    final s = archive.hostedStats();
    expect(s.totalItems, 4);
    expect(s.totalBytes, 7500);
    expect(s.strangerBytes, 6000);
    expect(s.strangerItems, 2);
    expect(s.followedBytes, 1000);
    expect(s.pinnedItems, 1);
  });

  test('the biggest depositors are the row a person can act on', () {
    seed();
    final top = archive.hostedByOrigin(limit: 3);
    expect(top.first.originPub, 'a' * 64);
    expect(top.first.bytes, 4000);
    expect(top.first.items, 1);
  });

  test('a preview says what a sweep would free, and frees nothing', () {
    seed();
    final p = archive.previewSweep(const HostedSweep.strangers());
    expect(p.bytes, 6000);
    expect(p.items, 2);
    expect(archive.hostedStats().totalItems, 4, reason: 'nothing was deleted');
  });

  test('dropping strangers leaves followed authors — and what I chose to keep',
      () {
    seed();
    final r = archive.sweepHosted(const HostedSweep.strangers());
    expect(r.items, 2);
    final s = archive.hostedStats();
    expect(s.strangerItems, 0);
    expect(s.followedItems, 1, reason: 'a followed author is not a stranger');
    expect(s.pinnedItems, 1,
        reason: 'the archive never deletes what the owner asked to keep');
  });

  test('older-than frees the old ones only', () {
    final now = DateTime.now().millisecondsSinceEpoch;
    seed(nowMs: now);
    final r = archive.sweepHosted(const HostedSweep.olderThan(30 * day),
        nowMs: now);
    expect(r.items, 1);
    expect(r.bytes, 4000);
  });

  test('never-served is dead weight by definition, and goes first', () {
    seed();
    final p = archive.previewSweep(const HostedSweep.neverServed());
    expect(p.items, 2, reason: 'nobody has fetched either stranger blob');
  });

  test('free-N-bytes takes strangers, oldest first, and stops when it has enough',
      () {
    seed();
    final r = archive.sweepHosted(const HostedSweep.freeBytes(3000));
    expect(r.bytes, greaterThanOrEqualTo(3000));
    final s = archive.hostedStats();
    expect(s.pinnedItems, 1);
    expect(s.followedItems, 1,
        reason: 'strangers were enough; it stopped before touching a friend');
  });

  test('"free a gigabyte" from a small archive does NOT eat my friends', () {
    seed();
    // Asking for far more than the strangers hold. The naive implementation
    // walks on into followed media to hit the number — which is the eviction
    // attack, performed by us, on request.
    final r = archive.sweepHosted(const HostedSweep.freeBytes(1 << 30));
    expect(r.bytes, 6000, reason: 'it freed the strangers and stopped');
    final s = archive.hostedStats();
    expect(s.followedItems, 1);
    expect(s.pinnedItems, 1);
  });

  test('"free space" gives back everything held for OTHERS, and nothing else',
      () {
    seed();
    final p = archive.previewSweep(const HostedSweep.all());
    expect(p.items, 3, reason: 'two strangers + one followed author');
    expect(p.bytes, 7000);
    expect(archive.hostedStats().totalItems, 4, reason: 'preview frees nothing');

    final r = archive.sweepHosted(const HostedSweep.all());
    expect(r.items, 3);
    final s = archive.hostedStats();
    expect(s.strangerItems, 0);
    expect(s.followedItems, 0);
    expect(s.pinnedItems, 1,
        reason: 'what the owner asked to keep is not the archive\'s to delete');
  });

  test('one depositor can be evicted on their own', () {
    seed();
    final r = archive.sweepHosted(HostedSweep.byOrigin('a' * 64));
    expect(r.items, 1);
    expect(r.bytes, 4000);
    expect(archive.hostedStats().strangerItems, 1);
  });
}
