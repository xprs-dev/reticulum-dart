/*
 * KeepPolicy — "to touch it is to keep it" (docs/NOSTR.md, the bridge).
 *
 * A like is not a fleeting gesture. It is a statement that this thing mattered,
 * and it is the cheapest true signal we will ever get about what is worth
 * preserving. So when the user interacts with an event, we archive the EVENT —
 * not merely their reaction to it — on their own relay, at tier 0, and serve it
 * from there over Reticulum. The public relay it came from can then rot, go
 * paid, or vanish, and nothing the user cared about goes with it.
 *
 * What a touch keeps:
 *   the target note            — the thing itself
 *   its author's kind-0        — a note whose author is anonymous in ten years
 *                                is half a memory
 *   the thread above a reply   — a reply with no context is worthless later
 *   the media it references    — pulled from Blossom NOW, while the internet is
 *                                still there; that is the whole point
 *
 * This file is the PLANNER (pure, no IO) plus a thin applier over the store.
 * Fetching what is missing is the caller's job: it owns the relays, the mesh and
 * the media archive, and it knows what the user has agreed to pay for (media on
 * cellular, size caps). We only say what is worth having.
 */
import '../../util/nostr_event.dart';
// NostrFilter lives in relay_event_store.dart
import 'relay_event_store.dart';

/// The kinds of interaction that count as "I meant this".
enum Touch {
  /// kind 7 — a reaction (like, upvote, emoji).
  react,

  /// kind 1 carrying an `e` tag — a reply.
  reply,

  /// kind 6, or a kind 1 quoting another note.
  repost,

  /// An explicit save. The honest form of the same act.
  bookmark,

  /// A payment. You certainly meant it.
  zap,
}

/// How deep a reply's ancestry is worth chasing. A thread with a thousand
/// parents is a mailing list, not a conversation — and an unbounded walk is a
/// free denial-of-service for whoever crafts one.
const int kMaxThreadDepth = 12;

/// The biggest media reference set we will chase for one touch. A note is free
/// to carry twenty pictures; we are not obliged to mirror all of them.
const int kMaxMediaPerNote = 6;

/// What a touch decided is worth keeping. Everything in here is content-
/// addressed or key-addressed, so applying the same plan twice is harmless.
class KeepPlan {
  /// Event ids to pin at tier 0 (already stored → promote; not stored → fetch,
  /// then store at tier 0).
  final List<String> pinIds;

  /// Event ids we do not have yet and must fetch before we can pin them.
  final List<String> fetchIds;

  /// Authors whose kind-0 profile we should have and do not.
  final List<String> fetchProfiles;

  /// Media the kept notes reference: `file:<b64>.<ext>` tokens, http(s) urls and
  /// bare sha256 hex — whatever the caller's media archive understands.
  final List<String> fetchMedia;

  const KeepPlan({
    this.pinIds = const [],
    this.fetchIds = const [],
    this.fetchProfiles = const [],
    this.fetchMedia = const [],
  });

  bool get isEmpty =>
      pinIds.isEmpty &&
      fetchIds.isEmpty &&
      fetchProfiles.isEmpty &&
      fetchMedia.isEmpty;

  @override
  String toString() => 'KeepPlan(pin=${pinIds.length}, fetch=${fetchIds.length}, '
      'profiles=${fetchProfiles.length}, media=${fetchMedia.length})';
}

/// Media references inside a note's content. Deliberately generous about what a
/// reference looks like, because the point is to notice the picture, not to be
/// right about its syntax:
///   - `file:<43 url-safe base64 chars>.<ext>` — our own media tokens
///   - `https://…/<64 hex>[.ext]`             — Blossom (the sha256 IS the name)
///   - `https://….(jpg|png|…)`                — a plain inline image/video
List<String> mediaRefsIn(String content, {int max = kMaxMediaPerNote}) {
  final out = <String>[];
  void add(String s) {
    if (out.length < max && !out.contains(s)) out.add(s);
  }

  for (final m in _fileToken.allMatches(content)) {
    add(m.group(0)!);
  }
  for (final m in _url.allMatches(content)) {
    final url = m.group(0)!;
    if (_blossomish.hasMatch(url) || _inlineMedia.hasMatch(url)) add(url);
  }
  return out;
}

final RegExp _fileToken = RegExp(r'file:[A-Za-z0-9_-]{43}\.[a-z0-9]{1,18}');
final RegExp _url = RegExp(r'https?://[^\s<>"]+');
final RegExp _blossomish = RegExp(r'/[0-9a-f]{64}(\.[A-Za-z0-9]{1,8})?$');
final RegExp _inlineMedia = RegExp(
  r'\.(jpg|jpeg|png|gif|webp|bmp|mp4|mov|webm|m4v|mp3|ogg|opus|pdf)(\?[^\s]*)?$',
  caseSensitive: false,
);

/// The note an interaction points at: the LAST `e` tag, which is the NIP-10
/// convention for "the thing I am replying/reacting to" (the earlier ones are
/// the thread above it). Null when there is no `e` tag at all.
String? targetOf(NostrEvent interaction) {
  String? last;
  for (final t in interaction.tags) {
    if (t.length >= 2 && t[0] == 'e' && t[1].isNotEmpty) last = t[1];
  }
  return last;
}

/// Plan what to keep when the user performs [touch] on [target].
///
/// [target] may be null when we do not hold the note yet (the user liked
/// something straight out of a live feed and it was never stored): the plan then
/// says "fetch it, and come back" — call [planKeep] again once it lands, and the
/// second pass will chase its parents and its media.
///
/// [store] is read, never written. [alreadyHave] lets a caller answer the
/// "do we hold this" questions from somewhere other than the store (a test, a
/// buffer) — it defaults to the store.
KeepPlan planKeep({
  required Touch touch,
  required String targetId,
  NostrEvent? target,
  required RelayEventStore store,
}) {
  final pin = <String>[targetId];
  final fetch = <String>[];
  final profiles = <String>[];
  final media = <String>[];

  if (target == null) {
    // We do not hold it yet. Fetching it IS the plan; the rest follows.
    return KeepPlan(pinIds: const [], fetchIds: [targetId]);
  }

  // The author, so the note still has a face in ten years.
  if (!store.hasProfile(target.pubkey)) profiles.add(target.pubkey);

  // The media, while the internet that holds it is still there.
  media.addAll(mediaRefsIn(target.content));

  // A reply is worthless without the conversation above it. Walk up the `e`
  // tags, bounded — through the store where we have the ancestors, and asking
  // for the ones we do not.
  if (touch == Touch.reply || _hasETag(target)) {
    var depth = 0;
    NostrEvent? cursor = target;
    final seen = <String>{targetId};
    while (cursor != null && depth < kMaxThreadDepth) {
      final parents = [
        for (final t in cursor.tags)
          if (t.length >= 2 && t[0] == 'e' && t[1].isNotEmpty) t[1]
      ];
      if (parents.isEmpty) break;
      // NIP-10: the last `e` tag is the direct parent; the first is the root.
      // Keep them all — a thread is the unit, not a link in it.
      NostrEvent? next;
      for (final pid in parents) {
        if (!seen.add(pid)) continue;
        pin.add(pid);
        final have = store.query(NostrFilter(ids: [pid], limit: 1));
        if (have.isEmpty) {
          fetch.add(pid);
        } else {
          final ev = have.first;
          if (!store.hasProfile(ev.pubkey)) profiles.add(ev.pubkey);
          for (final ref in mediaRefsIn(ev.content)) {
            if (!media.contains(ref)) media.add(ref);
          }
          next ??= ev;
        }
      }
      cursor = next;
      depth++;
    }
  }

  return KeepPlan(
    pinIds: pin.toSet().toList(),
    fetchIds: fetch.toSet().toList(),
    fetchProfiles: profiles.toSet().toList(),
    fetchMedia: media,
  );
}

bool _hasETag(NostrEvent e) =>
    e.tags.any((t) => t.length >= 2 && t[0] == 'e' && t[1].isNotEmpty);

/// Apply the storage half of a plan: promote everything we already hold to tier
/// 0 so it can never be evicted as a stranger's junk. Returns how many events
/// changed tier. The fetching half ([KeepPlan.fetchIds] etc.) belongs to the
/// caller — it owns the network.
int applyKeep(KeepPlan plan, RelayEventStore store) {
  var pinned = 0;
  for (final id in plan.pinIds) {
    if (store.pin(id)) pinned++;
  }
  return pinned;
}
