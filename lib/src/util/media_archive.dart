// Content-addressed local media archive (XPRS.md section 16.5).
//
// Stores the raw bytes of files referenced by `file:<sha256>.<ext>` tokens
// (see media_ref.dart), keyed by the unpadded-base64url SHA-256 of the bytes
// — so identical content is stored exactly once no matter how many messages
// or wapps reference it. Alongside the data each entry keeps room for the
// metadata the archive is expected to grow into: when the entry was first and
// last accessed, the original file name, free-form tags, a TLSH fuzzy hash
// (reserved — no Dart implementation exists yet), the SHA-1, a reusable
// preview screenshot, and a description.
//
// Backed by a zxdb file (media.zx, through dbOpener: encrypted inside an
// encrypted profile). Tables:
//   media       one row per held file: metadata only, no bytes
//   media_part  the bytes, in [partSize] pieces keyed (sha256, n): a ranged
//               read loads only the pieces it covers, and identical pieces
//               share their pages (zx deduplicates whole overflow values)
//   media_shot  the preview screenshot, apart from list views
//   sources     where a hash can be obtained from
// and the zx text index `media` (name, description, tags, folder, parent)
// for local search. Every change to a file is one transaction.
//
// How media bytes travel between stations is OUT OF SCOPE here — the archive
// only answers "do I have the bytes for this hash" locally.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:zx/zxdb.dart' show ZxSqlDbTextIndex;

import 'db_opener.dart';

import 'media_ref.dart';
import 'file_system.dart';

// Pure-Dart logging shim (this package has no Flutter dependency).
void debugPrint(Object? message) {
  assert(() {
    // ignore: avoid_print
    print(message);
    return true;
  }());
}

/// Non-blob metadata of one archive entry (cheap to query for list views).
/// What a cleanup sweep targets. Every option answers a question a person
/// actually asks when the disk is full: "whose is this?", "is any of it even
/// being used?", "how do I get a gigabyte back?".
enum SweepKind {
  /// Everything held for strangers. Never touches followed authors or our own.
  strangers,

  /// Anything accepted before a cut-off.
  olderThan,

  /// Stranger blobs nobody has ever fetched from us. Dead weight by definition.
  neverServed,

  /// Everything one depositor put here.
  byOrigin,

  /// Free up to N bytes from the STRANGER slice, oldest first. It never reaches
  /// into a followed author's media, however short it falls of the target.
  freeBytes,

  /// Everything this device holds FOR OTHERS — strangers and followed authors
  /// alike. Still never the owner's own media, and never what they pinned: the
  /// archive is the space volunteered, and giving it back is the owner's right.
  all,
}

class HostedSweep {
  final SweepKind kind;
  final int olderThanMs;
  final int freeBytes;
  final String originPub;

  const HostedSweep.strangers()
    : kind = SweepKind.strangers,
      olderThanMs = 0,
      freeBytes = 0,
      originPub = '';

  const HostedSweep.olderThan(this.olderThanMs)
    : kind = SweepKind.olderThan,
      freeBytes = 0,
      originPub = '';

  const HostedSweep.neverServed()
    : kind = SweepKind.neverServed,
      olderThanMs = 0,
      freeBytes = 0,
      originPub = '';

  const HostedSweep.byOrigin(this.originPub)
    : kind = SweepKind.byOrigin,
      olderThanMs = 0,
      freeBytes = 0;

  const HostedSweep.freeBytes(this.freeBytes)
    : kind = SweepKind.freeBytes,
      olderThanMs = 0,
      originPub = '';

  const HostedSweep.all()
    : kind = SweepKind.all,
      olderThanMs = 0,
      freeBytes = 0,
      originPub = '';
}

class MediaMeta {
  final String sha256; // unpadded base64url, 43 chars
  final String? sha1; // unpadded base64url, 27 chars
  final String? tlsh; // reserved: fuzzy hash, null until implemented
  final String? name; // original file name, when known
  final String ext; // lowercase extension (no dot)
  final String? description;
  final List<String> tags;
  final int firstSeenMs; // epoch ms of first insertion
  final int lastSeenMs; // epoch ms of last access
  final int size; // byte length of the data blob
  final bool hasScreenshot;
  final String? folder; // virtual folder name (categorization)
  final String? parent; // virtual parent-folder name
  final int downloads; // times served to others (metric)
  final bool pinned; // locally added/authored — never auto-evicted

  const MediaMeta({
    required this.sha256,
    required this.ext,
    required this.firstSeenMs,
    required this.lastSeenMs,
    required this.size,
    required this.hasScreenshot,
    this.sha1,
    this.tlsh,
    this.name,
    this.description,
    this.tags = const [],
    this.folder,
    this.parent,
    this.downloads = 0,
    this.pinned = true,
  });

  Map<String, dynamic> toJson() => {
    'sha256': sha256,
    if (sha1 != null) 'sha1': sha1,
    if (name != null) 'name': name,
    'ext': ext,
    if (description != null) 'description': description,
    'tags': tags,
    'firstSeen': firstSeenMs,
    'lastSeen': lastSeenMs,
    'size': size,
    'hasScreenshot': hasScreenshot,
    if (folder != null) 'folder': folder,
    if (parent != null) 'parent': parent,
    'downloads': downloads,
    'pinned': pinned,
  };
}

class MediaArchiveStats {
  final int count;
  final int totalBytes;
  final int screenshotCount;
  const MediaArchiveStats(this.count, this.totalBytes, this.screenshotCount);
}

/// One node in the virtual-folder tree (a distinct parent/folder grouping).
class MediaFolder {
  final String parent; // '' = top level
  final String folder; // '' = uncategorized within the parent
  final int count;
  const MediaFolder(this.parent, this.folder, this.count);

  Map<String, dynamic> toJson() => {
    'parent': parent,
    'folder': folder,
    'count': count,
  };
}

class MediaArchive {
  MediaArchive._(this._dbPath);

  /// Fired after bytes land, whichever door they came through: a chat
  /// download, a packet-lane assembly, a bulk-lane completion, a torrent, a
  /// user's own attach. Every lane ends in [putBytes] or [putHosted], so this
  /// is the one place "the file is here now" can be said once. Fires on the
  /// dedup branch too (the caller learns the file is held either way).
  /// Arguments: the 43-char base64url sha, the size in bytes, the extension.
  void Function(String sha256, int size, String ext)? onPut;

  void _notifyPut(String sha256, int size, String ext) {
    final cb = onPut;
    if (cb == null) return;
    try {
      cb(sha256, size, ext);
    } catch (_) {}
  }

  /// One archive per data root. Pass the SHARED wapp-data root (the parent of
  /// the per-wapp dirs, e.g. `wappsDataStorage(prefs)`) so every wapp on the
  /// profile sees the same content-addressed store.
  static final Map<String, MediaArchive> _instances = {};

  /// Open (or reuse) the archive stored under [directory] (one SQLite file per
  /// directory). The directory is created on first write.
  static MediaArchive forDirectory(String directory) => _instances.putIfAbsent(
    directory,
    () => MediaArchive._('$directory/$_fileName'),
  );

  static const String _fileName = 'media.zx';

  /// The size of one stored piece of a file (the last one is shorter).
  static const int partSize = 256 << 10;

  final String _dbPath;

  /// Where this archive's zxdb file lives. A caller that must move a large
  /// file (exporting it so the OS can open it) opens this path on a WORKER
  /// isolate and copies the pieces out with [partsOf], rather than pulling
  /// tens of MB through [get] on the isolate that draws the UI.
  String get dbPath => _dbPath;

  /// The pieces of file [key] (a [storageKeyOf] key) in [db], an open
  /// archive file, in order; nothing when it is not held. One piece at a
  /// time is on the heap.
  static Iterable<Uint8List> partsOf(ZxSqlDb db, String key) sync* {
    final count =
        db.select('SELECT COUNT(*) c FROM media_part WHERE sha256=?', [
              key,
            ]).first['c']
            as int;
    for (var n = 0; n < count; n++) {
      final r = db.select(
        'SELECT data FROM media_part WHERE sha256=? AND n=?',
        [key, n],
      );
      if (r.isEmpty) return;
      yield r.first['data'] as Uint8List;
    }
  }

  /// The storage key for a token / hex sha256 / b64u hash — the same
  /// normalisation [get] and [has] apply, exposed so an off-isolate reader can
  /// look a row up without duplicating the rules.
  static String? storageKeyOf(String tokenOrSha256) => _keyOf(tokenOrSha256);

  ZxSqlDb? _db;
  late ZxSqlDbTextIndex _fts; // set with _db
  bool _failed = false; // a fatal open error → operate degraded, never wipe

  // ── DB lifecycle ────────────────────────────────────────────────────────

  ZxSqlDb? _ensureDb() {
    if (_failed) return null;
    final existing = _db;
    if (existing != null) return existing;
    try {
      final parent = fileSystem.file(_dbPath).parent;
      if (!parent.existsSync()) parent.createSync(recursive: true);
      final db = openDb(_dbPath);
      db.execute('''
        CREATE TABLE IF NOT EXISTS media(
          sha256      TEXT PRIMARY KEY,
          sha1        TEXT,
          tlsh        TEXT,
          name        TEXT,
          ext         TEXT NOT NULL,
          description TEXT,
          tags        TEXT,
          first_seen  INTEGER NOT NULL,
          last_seen   INTEGER NOT NULL,
          size        INTEGER NOT NULL,
          shot        INTEGER NOT NULL DEFAULT 0,
          folder      TEXT,
          parent      TEXT,
          downloads   INTEGER NOT NULL DEFAULT 0,
          pinned      INTEGER NOT NULL DEFAULT 1,
          hosted      INTEGER NOT NULL DEFAULT 0,
          origin_pub  TEXT,
          tier        INTEGER NOT NULL DEFAULT 0,
          received_at INTEGER NOT NULL DEFAULT 0
        );
      ''');
      // folder/parent drive virtual-folder navigation; downloads is the
      // times-served-to-others metric; pinned protects locally added content
      // from the storage-budget evictor. Store-and-forward hosting: hosted=1
      // means we keep this file on behalf of others (a third-party deposit),
      // origin_pub is the depositing peer's pubkey (hex), tier is 0 self /
      // 1 followed / 2 stranger (tier-aware eviction), received_at is when we
      // accepted it (ms). shot = 1 when media_shot holds a screenshot.
      db.execute('CREATE INDEX IF NOT EXISTS idx_media_ext ON media(ext);');
      db.execute(
        'CREATE INDEX IF NOT EXISTS idx_media_last ON media(last_seen);',
      );
      db.execute(
        'CREATE INDEX IF NOT EXISTS idx_media_hosted ON media(hosted, tier, received_at);',
      );
      db.execute(
        'CREATE INDEX IF NOT EXISTS idx_media_folder ON media(parent, folder);',
      );
      db.execute('''
        CREATE TABLE IF NOT EXISTS media_part(
          sha256 TEXT NOT NULL,
          n      INTEGER NOT NULL,
          data   BLOB NOT NULL,
          PRIMARY KEY (sha256, n)
        );
      ''');
      db.execute('''
        CREATE TABLE IF NOT EXISTS media_shot(
          sha256 TEXT PRIMARY KEY,
          data   BLOB NOT NULL
        );
      ''');
      // Where a hash can be obtained from (XPRS section 16 / Files wapp): announced
      // torrent infohashes, Blossom server base URLs, callsigns claiming the
      // file. Kept even for hashes we don't hold, so we can answer/relay.
      db.execute('''
        CREATE TABLE IF NOT EXISTS sources(
          sha256    TEXT NOT NULL,
          kind      TEXT NOT NULL,
          value     TEXT NOT NULL,
          last_seen INTEGER NOT NULL,
          PRIMARY KEY (sha256, kind, value)
        );
      ''');
      _fts = db.textIndex('media', const {
        'name': 1,
        'description': 1,
        'tags': 1,
        'folder': 1,
        'parent': 1,
      });
      _db = db;
      return db;
    } catch (e) {
      _failed = true;
      debugPrint('MediaArchive: open failed for $_dbPath: $e');
      return null;
    }
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  static String _b64u(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');

  /// Accept a full `file:<hash>.<ext>` token, a bare 43-char base64url hash,
  /// or a 64-char hex digest (the Blossom/NOSTR form).
  static String? _keyOf(String tokenOrSha256) {
    final ref = MediaRef.parse(tokenOrSha256);
    if (ref != null) return ref.sha256;
    if (RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(tokenOrSha256)) {
      return tokenOrSha256;
    }
    if (tokenOrSha256.length == 64) {
      return MediaRef.hexToB64u(tokenOrSha256);
    }
    return null;
  }

  static String _normExt(String ext) {
    var e = ext.toLowerCase();
    if (e.startsWith('.')) e = e.substring(1);
    if (!RegExp(r'^[a-z0-9]{1,18}$').hasMatch(e)) {
      throw ArgumentError('invalid media extension: $ext');
    }
    return e;
  }

  /// Max chars for a file description (host-enforced).
  static const int kMaxDescription = 250;
  static String? _clampDesc(String? d) => d == null
      ? null
      : (d.length > kMaxDescription ? d.substring(0, kMaxDescription) : d);

  /// Rebuild the text-index document for [key] from its media row.
  void _syncFts(ZxSqlDb db, String key) {
    final rows = db.select(
      'SELECT name,description,tags,folder,parent FROM media WHERE sha256=?',
      [key],
    );
    if (rows.isEmpty) {
      _fts.remove(key);
      return;
    }
    final r = rows.first;
    var tagsText = '';
    final rawTags = r['tags'];
    if (rawTags is String && rawTags.isNotEmpty) {
      try {
        tagsText = (jsonDecode(rawTags) as List).join(' ');
      } catch (_) {}
    }
    _fts.put(key, {
      'name': r['name'] as String?,
      'description': r['description'] as String?,
      'tags': tagsText,
      'folder': r['folder'] as String?,
      'parent': r['parent'] as String?,
    });
  }

  /// Free text as a text-index query: every word, the last one a prefix.
  static String? _ftsMatch(String text) {
    final terms = text
        .toLowerCase()
        .split(RegExp(r'[^\p{L}\p{N}]+', unicode: true))
        .where((t) => t.isNotEmpty)
        .toList();
    if (terms.isEmpty) return null;
    terms[terms.length - 1] = '${terms.last}*';
    return terms.join(' ');
  }

  /// Stores [data] as the pieces of [key] (inside the caller's transaction).
  static void _putParts(ZxSqlDb db, String key, Uint8List data) {
    for (var n = 0, at = 0; at < data.length || n == 0; n++, at += partSize) {
      final end = (at + partSize).clamp(0, data.length);
      db.execute(
        'INSERT OR REPLACE INTO media_part(sha256,n,data) VALUES(?,?,?)',
        [key, n, Uint8List.sublistView(data, at, end)],
      );
    }
  }

  /// Removes every row of [key] (inside the caller's transaction).
  void _deleteRows(ZxSqlDb db, String key) {
    db.execute('DELETE FROM media WHERE sha256=?', [key]);
    db.execute('DELETE FROM media_part WHERE sha256=?', [key]);
    db.execute('DELETE FROM media_shot WHERE sha256=?', [key]);
    _fts.remove(key);
  }

  // ── API ─────────────────────────────────────────────────────────────────

  /// Store [data]; returns the wire token `file:<sha256>.<ext>`. Identical
  /// content dedups onto the existing row (its last-accessed time is bumped;
  /// name/description/tags fill in only if they were empty).
  String putBytes(
    Uint8List data,
    String ext, {
    String? name,
    String? description,
    List<String>? tags,
  }) {
    final e = _normExt(ext);
    final key = _b64u(crypto.sha256.convert(data).bytes);
    final token = 'file:$key.$e';
    final db = _ensureDb();
    if (db == null) return token;
    final now = DateTime.now().millisecondsSinceEpoch;
    try {
      final sha1b64 = _b64u(crypto.sha1.convert(data).bytes);
      db.transaction(() {
        db.execute(
          'INSERT OR IGNORE INTO media'
          '(sha256,sha1,tlsh,name,ext,description,tags,'
          ' first_seen,last_seen,size) '
          'VALUES(?,?,NULL,?,?,?,?,?,?,?)',
          // TODO(tlsh): compute when a Dart TLSH implementation is available.
          [
            key,
            sha1b64,
            name,
            e,
            _clampDesc(description),
            tags == null ? null : jsonEncode(tags),
            now,
            now,
            data.length,
          ],
        );
        if (db.updatedRows == 0) {
          // Already archived: bump last_seen, backfill empty metadata.
          db.execute(
            'UPDATE media SET last_seen=?, '
            'name=COALESCE(name,?), description=COALESCE(description,?), '
            'tags=COALESCE(tags,?) WHERE sha256=?',
            [
              now,
              name,
              _clampDesc(description),
              tags == null ? null : jsonEncode(tags),
              key,
            ],
          );
        } else {
          _putParts(db, key, data);
        }
        _syncFts(db, key);
      });
    } catch (e2) {
      debugPrint('MediaArchive: putBytes failed: $e2');
      return token;
    }
    _notifyPut(key, data.length, e);
    return token;
  }

  // ── Store-and-forward hosting (third-party blobs) ─────────────────────────

  /// Store a blob we host ON BEHALF OF a peer (store-and-forward Blossom). Unlike
  /// putBytes (our own/downloaded media, pinned), this records provenance
  /// ([originPubHex] = depositor) and the retention [tier] (0 self / 1 followed /
  /// 2 stranger) so the evictor can drop it under storage pressure. If we already
  /// hold the bytes as our own (hosted=0), the row is left as our own. Returns the
  /// sha256 token.
  /// [pin] marks the blob as one the user deliberately KEEPS (see "keep data"
  /// on a profile): it stays hosted and served, but the eviction sweep will not
  /// consider it however tight the quota gets. Pinning is the only promise this
  /// archive makes that survives storage pressure, so it is opt-in per account.
  String putHosted(
    Uint8List data,
    String ext, {
    required String originPubHex,
    required int tier,
    int? receivedAtMs,
    bool pin = false,
  }) {
    final e = _normExt(ext);
    final key = _b64u(crypto.sha256.convert(data).bytes);
    final token = 'file:$key.$e';
    final db = _ensureDb();
    if (db == null) return token;
    final now = DateTime.now().millisecondsSinceEpoch;
    final rcv = receivedAtMs ?? now;
    try {
      final sha1b64 = _b64u(crypto.sha1.convert(data).bytes);
      db.transaction(() {
        db.execute(
          'INSERT OR IGNORE INTO media'
          '(sha256,sha1,tlsh,name,ext,description,tags,'
          ' first_seen,last_seen,size,pinned,hosted,origin_pub,tier,received_at) '
          'VALUES(?,?,NULL,NULL,?,NULL,NULL,?,?,?,?,1,?,?,?)',
          [
            key,
            sha1b64,
            e,
            now,
            now,
            data.length,
            pin ? 1 : 0,
            originPubHex,
            tier,
            rcv,
          ],
        );
        if (db.updatedRows > 0) {
          _putParts(db, key, data);
        } else {
          // Already present: bump last_seen, and let a pin UPGRADE an existing row
          // (the user turned "keep data" on after we already had the bytes).
          db.execute('UPDATE media SET last_seen=? WHERE sha256=?', [now, key]);
          if (pin) {
            db.execute('UPDATE media SET pinned=1 WHERE sha256=?', [key]);
          }
        }
        _syncFts(db, key);
      });
    } catch (e2) {
      debugPrint('MediaArchive: putHosted failed: $e2');
      return token;
    }
    _notifyPut(key, data.length, e);
    return token;
  }

  /// Hosted-blob byte totals for the deposit admission gate: ({strangerBytes,
  /// totalHostedBytes}). Our own/downloaded media (hosted=0) is excluded.
  ({int strangerBytes, int totalHostedBytes}) hostedTotals() {
    final db = _ensureDb();
    if (db == null) return (strangerBytes: 0, totalHostedBytes: 0);
    try {
      final s =
          db
                  .select(
                    'SELECT COALESCE(SUM(size),0) b FROM media WHERE hosted=1 AND tier=2',
                  )
                  .first['b']
              as int;
      final t =
          db
                  .select(
                    'SELECT COALESCE(SUM(size),0) b FROM media WHERE hosted=1',
                  )
                  .first['b']
              as int;
      return (strangerBytes: s, totalHostedBytes: t);
    } catch (_) {
      return (strangerBytes: 0, totalHostedBytes: 0);
    }
  }

  /// Aggregate statistics about what this device is holding FOR OTHERS.
  ///
  /// Statistics, not a list: an archive is expected to hold hundreds of
  /// thousands of blobs, and a user scrolling that list learns nothing and can
  /// do nothing. What they need is where the space went and how to get it back.
  /// All of it is one SQL pass, so it stays cheap at any size.
  ({
    int totalBytes,
    int totalItems,
    int strangerBytes,
    int strangerItems,
    int followedBytes,
    int followedItems,
    int pinnedBytes,
    int pinnedItems,
    int oldestMs,
    int servedItems,
  })
  hostedStats() {
    final db = _ensureDb();
    const empty = (
      totalBytes: 0,
      totalItems: 0,
      strangerBytes: 0,
      strangerItems: 0,
      followedBytes: 0,
      followedItems: 0,
      pinnedBytes: 0,
      pinnedItems: 0,
      oldestMs: 0,
      servedItems: 0,
    );
    if (db == null) return empty;
    try {
      final r = db
          .select(
            'SELECT '
            ' COALESCE(SUM(size),0) tb, COUNT(*) ti,'
            ' COALESCE(SUM(CASE WHEN tier=2 THEN size ELSE 0 END),0) sb,'
            ' COALESCE(SUM(CASE WHEN tier=2 THEN 1 ELSE 0 END),0) si,'
            ' COALESCE(SUM(CASE WHEN tier=1 THEN size ELSE 0 END),0) fb,'
            ' COALESCE(SUM(CASE WHEN tier=1 THEN 1 ELSE 0 END),0) fi,'
            ' COALESCE(SUM(CASE WHEN pinned=1 THEN size ELSE 0 END),0) pb,'
            ' COALESCE(SUM(CASE WHEN pinned=1 THEN 1 ELSE 0 END),0) pi,'
            ' COALESCE(MIN(received_at),0) oldest,'
            ' COALESCE(SUM(CASE WHEN downloads>0 THEN 1 ELSE 0 END),0) served'
            ' FROM media WHERE hosted=1',
          )
          .first;
      return (
        totalBytes: (r['tb'] as int?) ?? 0,
        totalItems: (r['ti'] as int?) ?? 0,
        strangerBytes: (r['sb'] as int?) ?? 0,
        strangerItems: (r['si'] as int?) ?? 0,
        followedBytes: (r['fb'] as int?) ?? 0,
        followedItems: (r['fi'] as int?) ?? 0,
        pinnedBytes: (r['pb'] as int?) ?? 0,
        pinnedItems: (r['pi'] as int?) ?? 0,
        oldestMs: (r['oldest'] as int?) ?? 0,
        servedItems: (r['served'] as int?) ?? 0,
      );
    } catch (_) {
      return empty;
    }
  }

  /// Who the space actually went to: the biggest depositors, largest first.
  /// This is the row a person can act on — "npub X is using 4 GB of my disk" —
  /// which a list of blobs never tells them.
  List<({String originPub, int bytes, int items})> hostedByOrigin({
    int limit = 10,
  }) {
    final db = _ensureDb();
    if (db == null) return const [];
    try {
      final rows = db.select(
        'SELECT COALESCE(origin_pub, ?) op, SUM(size) b, COUNT(*) n '
        'FROM media WHERE hosted=1 GROUP BY op ORDER BY b DESC LIMIT ?',
        ['', limit],
      );
      return [
        for (final r in rows)
          (
            originPub: (r['op'] as String?) ?? '',
            bytes: (r['b'] as int?) ?? 0,
            items: (r['n'] as int?) ?? 0,
          ),
      ];
    } catch (_) {
      return const [];
    }
  }

  /// How much [sweep] would free, without freeing it. A cleanup tool that cannot
  /// tell you what it is about to delete is not a tool, it is a gamble.
  ({int bytes, int items}) previewSweep(HostedSweep sweep, {int? nowMs}) =>
      _sweep(sweep, nowMs: nowMs, dryRun: true);

  /// Free space. Never touches PINNED blobs (the user asked for those) and never
  /// touches our own media (hosted=0) — only what we volunteered to hold for
  /// other people.
  ({int bytes, int items}) sweepHosted(HostedSweep sweep, {int? nowMs}) =>
      _sweep(sweep, nowMs: nowMs, dryRun: false);

  ({int bytes, int items}) _sweep(
    HostedSweep sweep, {
    int? nowMs,
    required bool dryRun,
  }) {
    final db = _ensureDb();
    if (db == null) return (bytes: 0, items: 0);
    final now = nowMs ?? DateTime.now().millisecondsSinceEpoch;

    final where = StringBuffer('hosted=1 AND pinned=0');
    final params = <Object?>[];
    switch (sweep.kind) {
      case SweepKind.strangers:
        where.write(' AND tier=2');
      case SweepKind.olderThan:
        where.write(' AND received_at < ?');
        params.add(now - sweep.olderThanMs);
      case SweepKind.neverServed:
        where.write(' AND downloads=0 AND tier=2');
      case SweepKind.byOrigin:
        where.write(' AND origin_pub = ?');
        params.add(sweep.originPub);
      case SweepKind.freeBytes:
        break; // handled below: oldest first until enough is freed
      case SweepKind.all:
        break; // the base clause (hosted, not pinned) IS the filter
    }

    try {
      if (sweep.kind == SweepKind.freeBytes) {
        // ONLY the stranger slice. "Free 1 GB" must never reach into the media
        // of the people the owner follows: they did not ask to lose that, and a
        // cleanup that quietly took it would be the eviction attack, performed
        // by us, on request. If the strangers do not add up to the target, we
        // free what there is and stop — an honest partial beats a destructive
        // whole.
        final rows = db.select(
          'SELECT sha256, size FROM media WHERE hosted=1 AND pinned=0 '
          'AND tier=2 ORDER BY received_at ASC',
        );
        var freed = 0;
        final drop = <String>[];
        for (final r in rows) {
          if (freed >= sweep.freeBytes) break;
          freed += (r['size'] as int?) ?? 0;
          drop.add(r['sha256'] as String);
        }
        if (!dryRun) _deleteAll(db, drop);
        return (bytes: freed, items: drop.length);
      }

      final agg = db
          .select(
            'SELECT COALESCE(SUM(size),0) b, COUNT(*) n FROM media WHERE $where',
            params,
          )
          .first;
      final bytes = (agg['b'] as int?) ?? 0;
      final items = (agg['n'] as int?) ?? 0;
      if (!dryRun && items > 0) {
        final rows = db.select('SELECT sha256 FROM media WHERE $where', params);
        _deleteAll(db, [for (final r in rows) r['sha256'] as String]);
      }
      return (bytes: bytes, items: items);
    } catch (_) {
      return (bytes: 0, items: 0);
    }
  }

  /// Inventory of hosted blobs for the eviction planner: each is media (a blob),
  /// with its tier, size and accept time. Our own media (hosted=0) is never here.
  List<({String sha, int tier, int bytes, int receivedAtMs})>
  hostedInventory() {
    final db = _ensureDb();
    if (db == null) return const [];
    try {
      // pinned=0 only: a pinned blob is one the user asked this device to keep,
      // and handing it to the evictor would break exactly that promise.
      final rows = db.select(
        'SELECT sha256, tier, size, received_at FROM media '
        'WHERE hosted=1 AND pinned=0',
      );
      return [
        for (final r in rows)
          (
            sha: r['sha256'] as String,
            tier: (r['tier'] as int?) ?? 2,
            bytes: (r['size'] as int?) ?? 0,
            receivedAtMs: (r['received_at'] as int?) ?? 0,
          ),
      ];
    } catch (_) {
      return const [];
    }
  }

  /// The raw bytes for a token or bare hash (null when absent). A hit counts
  /// as an access: last-accessed is bumped.
  Uint8List? get(String tokenOrSha256) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null) return null;
    try {
      final size = sizeOf(key);
      if (size == null) return null;
      final out = BytesBuilder(copy: false);
      for (final part in partsOf(db, key)) {
        out.add(part);
      }
      if (out.length != size) return null; // a damaged entry
      touch(key);
      return out.takeBytes();
    } catch (e) {
      debugPrint('MediaArchive: get failed: $e');
      return null;
    }
  }

  /// The byte length of a held entry, from its `size` column: no blob read.
  /// Null when absent.
  int? sizeOf(String tokenOrSha256) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null) return null;
    try {
      final rows = db.select('SELECT size FROM media WHERE sha256=?', [key]);
      if (rows.isEmpty) return null;
      return rows.first['size'] as int;
    } catch (e) {
      debugPrint('MediaArchive: sizeOf failed: $e');
      return null;
    }
  }

  /// Bytes `[offset, offset+length)` of a held entry, read from the pieces
  /// it covers only, so serving one piece of a 16 MB file does not put 16 MB
  /// on the heap (docs/performance.md 8.9).
  /// Null when absent or [offset] is past the end. Not counted as an access:
  /// a swarm asking for 256 pieces is one fetch, not 256.
  Uint8List? readRange(String tokenOrSha256, int offset, int length) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null || offset < 0 || length <= 0) return null;
    try {
      final size = sizeOf(key);
      if (size == null || offset >= size) return null;
      final end = (offset + length).clamp(0, size);
      final out = BytesBuilder(copy: false);
      for (final r in db.select(
        'SELECT n, data FROM media_part WHERE sha256=? AND n>=? AND n<=? '
        'ORDER BY n',
        [key, offset ~/ partSize, (end - 1) ~/ partSize],
      )) {
        final base = (r['n'] as int) * partSize;
        final data = r['data'] as Uint8List;
        final from = (offset - base).clamp(0, data.length);
        final to = (end - base).clamp(0, data.length);
        if (to > from) out.add(Uint8List.sublistView(data, from, to));
      }
      return out.takeBytes();
    } catch (e) {
      debugPrint('MediaArchive: readRange failed: $e');
      return null;
    }
  }

  /// Bump last-accessed without reading the blob (e.g. a token was seen
  /// on-air and the bytes are already here).
  void touch(String tokenOrSha256) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null) return;
    try {
      db.execute('UPDATE media SET last_seen=? WHERE sha256=?', [
        DateTime.now().millisecondsSinceEpoch,
        key,
      ]);
    } catch (e) {
      debugPrint('MediaArchive: touch failed: $e');
    }
  }

  /// True when the archive holds the bytes for this token / hash.
  bool has(String tokenOrSha256) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null) return false;
    try {
      return db.select('SELECT 1 FROM media WHERE sha256=?', [key]).isNotEmpty;
    } catch (_) {
      return false;
    }
  }

  /// Metadata (everything but the blobs) — cheap for list views.
  MediaMeta? getMeta(String tokenOrSha256) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null) return null;
    try {
      final rows = db.select(
        'SELECT sha256,sha1,tlsh,name,ext,description,tags,first_seen,'
        'last_seen,size,folder,parent,downloads,pinned,'
        'shot AS has_shot '
        'FROM media WHERE sha256=?',
        [key],
      );
      if (rows.isEmpty) return null;
      final r = rows.first;
      List<String> tags = const [];
      final rawTags = r['tags'];
      if (rawTags is String && rawTags.isNotEmpty) {
        try {
          tags = (jsonDecode(rawTags) as List).map((t) => '$t').toList();
        } catch (_) {}
      }
      return MediaMeta(
        sha256: r['sha256'] as String,
        sha1: r['sha1'] as String?,
        tlsh: r['tlsh'] as String?,
        name: r['name'] as String?,
        ext: r['ext'] as String,
        description: r['description'] as String?,
        tags: tags,
        firstSeenMs: r['first_seen'] as int,
        lastSeenMs: r['last_seen'] as int,
        size: r['size'] as int,
        hasScreenshot: (r['has_shot'] as int) != 0,
        folder: r['folder'] as String?,
        parent: r['parent'] as String?,
        downloads: (r['downloads'] as int?) ?? 0,
        pinned: ((r['pinned'] as int?) ?? 1) != 0,
      );
    } catch (e) {
      debugPrint('MediaArchive: getMeta failed: $e');
      return null;
    }
  }

  /// Update mutable metadata; null arguments leave the column unchanged.
  /// [description] is clamped to [kMaxDescription] chars. [folder]/[parent]
  /// drive the virtual-folder navigation. The FTS index is kept in sync.
  void updateMeta(
    String tokenOrSha256, {
    String? name,
    String? description,
    List<String>? tags,
    String? folder,
    String? parent,
  }) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null) return;
    try {
      db.transaction(() {
        db.execute(
          'UPDATE media SET name=COALESCE(?,name), '
          'description=COALESCE(?,description), tags=COALESCE(?,tags), '
          'folder=COALESCE(?,folder), parent=COALESCE(?,parent) '
          'WHERE sha256=?',
          [
            name,
            _clampDesc(description),
            tags == null ? null : jsonEncode(tags),
            folder,
            parent,
            key,
          ],
        );
        _syncFts(db, key);
      });
    } catch (e) {
      debugPrint('MediaArchive: updateMeta failed: $e');
    }
  }

  /// Store (or replace) the reusable preview screenshot for an entry.
  void setScreenshot(String tokenOrSha256, Uint8List screenshot) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null) return;
    try {
      db.transaction(() {
        if (!has(key)) return;
        db.execute(
          'INSERT OR REPLACE INTO media_shot(sha256,data) VALUES(?,?)',
          [key, screenshot],
        );
        db.execute('UPDATE media SET shot=1 WHERE sha256=?', [key]);
      });
    } catch (e) {
      debugPrint('MediaArchive: setScreenshot failed: $e');
    }
  }

  /// The preview screenshot bytes, or null when none was stored.
  Uint8List? getScreenshot(String tokenOrSha256) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null) return null;
    try {
      final rows = db.select('SELECT data FROM media_shot WHERE sha256=?', [
        key,
      ]);
      if (rows.isEmpty) return null;
      return rows.first['data'] as Uint8List?;
    } catch (e) {
      debugPrint('MediaArchive: getScreenshot failed: $e');
      return null;
    }
  }

  /// Remove an entry (data + metadata). No-op when absent.
  void delete(String tokenOrSha256) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null) return;
    try {
      db.transaction(() => _deleteRows(db, key));
    } catch (e) {
      debugPrint('MediaArchive: delete failed: $e');
    }
  }

  /// Removes [keys] in one transaction, then compacts the file when the
  /// removed bytes made it worth it.
  void _deleteAll(ZxSqlDb db, List<String> keys) {
    if (keys.isEmpty) return;
    db.transaction(() {
      for (final k in keys) {
        _deleteRows(db, k);
      }
    });
    try {
      db.maybeCompact();
    } catch (e) {
      debugPrint('MediaArchive: compaction failed: $e');
    }
  }

  /// Page through the archive's metadata, most recently accessed first
  /// (cheap: never touches the blobs).
  List<MediaMeta> list({int offset = 0, int limit = 100}) {
    final db = _ensureDb();
    if (db == null) return const [];
    try {
      final rows = db.select(
        'SELECT sha256 FROM media ORDER BY last_seen DESC LIMIT ? OFFSET ?',
        [limit, offset],
      );
      return [for (final r in rows) ?getMeta(r['sha256'] as String)];
    } catch (e) {
      debugPrint('MediaArchive: list failed: $e');
      return const [];
    }
  }

  /// Full-text search over name/description/tags/folder/parent (local index).
  /// Best matches first (BM25), then most-recently accessed.
  List<MediaMeta> search(String query, {int limit = 50}) {
    final db = _ensureDb();
    if (db == null) return const [];
    final q = _ftsMatch(query);
    if (q == null) return const [];
    try {
      final hits = _fts.search(q, limit: limit * 4 + 50);
      final metas =
          [
            for (final h in hits)
              if (getMeta(h.key) case final m?) (h.score, m),
          ]..sort((a, b) {
            final c = b.$1.compareTo(a.$1);
            return c != 0 ? c : b.$2.lastSeenMs.compareTo(a.$2.lastSeenMs);
          });
      return [for (final m in metas.take(limit)) m.$2];
    } catch (e) {
      debugPrint('MediaArchive: search failed: $e');
      return const [];
    }
  }

  /// Exact lookup by a sha256 (token, base64url, or 64-char hex). Null if absent.
  MediaMeta? lookupBySha(String shaOrToken) => getMeta(shaOrToken);

  /// Increment the times-served-to-others counter for a file (the download
  /// metric). No-op when the file isn't held.
  void incrementDownloads(String tokenOrSha256) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null) return;
    try {
      db.execute('UPDATE media SET downloads = downloads + 1 WHERE sha256=?', [
        key,
      ]);
    } catch (e) {
      debugPrint('MediaArchive: incrementDownloads failed: $e');
    }
  }

  /// The virtual-folder tree: one entry per distinct (parent, folder) with a
  /// file count, for navigation. Empty parent/folder means "uncategorized".
  List<MediaFolder> folders() {
    final db = _ensureDb();
    if (db == null) return const [];
    try {
      final rows = db.select(
        "SELECT COALESCE(parent,'') p, COALESCE(folder,'') f, COUNT(*) c "
        'FROM media GROUP BY p, f ORDER BY p, f',
      );
      return [
        for (final r in rows)
          MediaFolder(r['p'] as String, r['f'] as String, r['c'] as int),
      ];
    } catch (e) {
      debugPrint('MediaArchive: folders failed: $e');
      return const [];
    }
  }

  /// Files in a given virtual (parent, folder), most recently accessed first.
  /// Pass empty strings for the uncategorized bucket.
  List<MediaMeta> listByFolder(
    String parent,
    String folder, {
    int offset = 0,
    int limit = 200,
  }) {
    final db = _ensureDb();
    if (db == null) return const [];
    try {
      final rows = db.select(
        "SELECT sha256 FROM media WHERE COALESCE(parent,'')=? "
        "AND COALESCE(folder,'')=? ORDER BY last_seen DESC LIMIT ? OFFSET ?",
        [parent, folder, limit, offset],
      );
      return [for (final r in rows) ?getMeta(r['sha256'] as String)];
    } catch (e) {
      debugPrint('MediaArchive: listByFolder failed: $e');
      return const [];
    }
  }

  // ── Sources: where a hash can be obtained from ─────────────────────────

  /// Record that [value] (an `infohash`, a `blossom` base URL, or a
  /// `callsign`) can provide [tokenOrSha256]. Idempotent; bumps last_seen.
  void addSource(String tokenOrSha256, String kind, String value) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null || value.isEmpty) return;
    try {
      db.execute(
        'INSERT INTO sources(sha256,kind,value,last_seen) VALUES(?,?,?,?) '
        'ON CONFLICT(sha256,kind,value) DO UPDATE SET last_seen=excluded.last_seen',
        [key, kind, value, DateTime.now().millisecondsSinceEpoch],
      );
    } catch (e) {
      debugPrint('MediaArchive: addSource failed: $e');
    }
  }

  /// Known providers for a hash, newest first. [kind] filters when given.
  List<(String kind, String value)> getSources(
    String tokenOrSha256, {
    String? kind,
  }) {
    final key = _keyOf(tokenOrSha256);
    final db = _ensureDb();
    if (key == null || db == null) return const [];
    try {
      final rows = kind == null
          ? db.select(
              'SELECT kind,value FROM sources WHERE sha256=? '
              'ORDER BY last_seen DESC',
              [key],
            )
          : db.select(
              'SELECT kind,value FROM sources WHERE sha256=? AND kind=? '
              'ORDER BY last_seen DESC',
              [key, kind],
            );
      return [
        for (final r in rows) (r['kind'] as String, r['value'] as String),
      ];
    } catch (_) {
      return const [];
    }
  }

  /// Archive size summary (diagnostics / a future storage-settings page).
  MediaArchiveStats stats() {
    final db = _ensureDb();
    if (db == null) return const MediaArchiveStats(0, 0, 0);
    try {
      final r = db
          .select(
            'SELECT COUNT(*) AS n, COALESCE(SUM(size),0) AS b, '
            'SUM(shot) AS s FROM media',
          )
          .first;
      return MediaArchiveStats(
        r['n'] as int,
        r['b'] as int,
        (r['s'] as int?) ?? 0,
      );
    } catch (_) {
      return const MediaArchiveStats(0, 0, 0);
    }
  }

  /// Bound the archive: drop entries last accessed more than [maxAgeMs] ago,
  /// then keep only the [maxCount] most recently accessed.
  void prune({int maxAgeMs = 365 * 24 * 60 * 60 * 1000, int maxCount = 10000}) {
    final db = _ensureDb();
    if (db == null) return;
    try {
      final cutoff = DateTime.now().millisecondsSinceEpoch - maxAgeMs;
      _deleteAll(db, [
        for (final r in db.select(
          'SELECT sha256 FROM media WHERE last_seen < ? UNION '
          'SELECT sha256 FROM (SELECT sha256 FROM media '
          'ORDER BY last_seen DESC LIMIT 9223372036854775807 OFFSET ?)',
          [cutoff, maxCount],
        ))
          r['sha256'] as String,
      ]);
    } catch (e) {
      debugPrint('MediaArchive: prune failed: $e');
    }
  }

  /// Close the database (tests / teardown).
  void close() {
    try {
      _db?.dispose();
    } catch (_) {}
    _db = null;
    _instances.removeWhere((_, v) => identical(v, this));
  }
}
