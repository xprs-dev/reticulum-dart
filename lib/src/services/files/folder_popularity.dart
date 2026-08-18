/*
 * FolderPopularity — how popular a shared folder is over time, kept ON THIS
 * DEVICE (never in the folder), so we can graph seeders and unique leechers per
 * month and appreciate a torrent's reach.
 *
 * Lean by design. Only the CURRENT month keeps the raw unique observations
 * (`pop_live`: one row per distinct seeder/leecher id). Once a month is over it
 * is rolled up to two totals (`pop_month`: seeders, leechers) and the raw rows
 * are deleted — so a folder shared for years costs a handful of integer rows,
 * not a growing set of peer ids.
 *
 *   seeder  = a holder the Indexers report (its files-destination hash, stable
 *             across sessions) — sampled whenever the swarm is resolved.
 *   leecher = a peer that downloaded a file of this folder FROM US (its serve
 *             link id) — recorded at serve time. A session-unique proxy for a
 *             downloader, which is what a popularity graph wants.
 *
 * Path-injectable (':memory:' for tests). Synchronous; headless. Time is passed
 * in (`nowMs`) so it is testable and never reaches for a wall clock itself.
 */
import 'package:sqlite3/sqlite3.dart';

import '../../util/db_opener.dart';

/// One month of popularity: [ym] = year*100 + month (e.g. 202607).
class PopMonth {
  final int ym;
  final int seeders;
  final int leechers;
  const PopMonth(this.ym, this.seeders, this.leechers);

  Map<String, int> toJson() => {'ym': ym, 'seeders': seeders, 'leechers': leechers};
}

class FolderPopularity {
  final Database _db;
  FolderPopularity._(this._db);

  factory FolderPopularity.open(String path) {
    final db = dbOpener(path);
    db.execute('PRAGMA journal_mode = WAL;');
    db.execute('PRAGMA synchronous = NORMAL;');
    // The current-ish months' raw unique ids (deleted on rollover).
    db.execute('''
      CREATE TABLE IF NOT EXISTS pop_live(
        folder TEXT NOT NULL,
        ym     INTEGER NOT NULL,
        kind   INTEGER NOT NULL,   -- 0 = seeder, 1 = leecher
        id     TEXT NOT NULL,
        PRIMARY KEY (folder, ym, kind, id)
      );
    ''');
    // Finalized monthly totals (kept forever — two ints per folder per month).
    db.execute('''
      CREATE TABLE IF NOT EXISTS pop_month(
        folder   TEXT NOT NULL,
        ym       INTEGER NOT NULL,
        seeders  INTEGER NOT NULL DEFAULT 0,
        leechers INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (folder, ym)
      );
    ''');
    return FolderPopularity._(db);
  }

  static int ymOf(int nowMs) {
    final d = DateTime.fromMillisecondsSinceEpoch(nowMs);
    return d.year * 100 + d.month;
  }

  /// Fold every finished month of raw rows (ym < the current one) into a total
  /// and drop the raw rows. Cheap and idempotent; called before every write.
  void _rollover(String folder, int curYm) {
    try {
      _db.execute(
        'INSERT INTO pop_month(folder, ym, seeders, leechers) '
        'SELECT folder, ym, '
        '  SUM(CASE WHEN kind=0 THEN 1 ELSE 0 END), '
        '  SUM(CASE WHEN kind=1 THEN 1 ELSE 0 END) '
        'FROM pop_live WHERE folder=? AND ym<? GROUP BY folder, ym '
        'ON CONFLICT(folder, ym) DO UPDATE SET '
        '  seeders=excluded.seeders, leechers=excluded.leechers',
        [folder, curYm],
      );
      _db.execute('DELETE FROM pop_live WHERE folder=? AND ym<?', [folder, curYm]);
    } catch (_) {}
  }

  /// Record the distinct seeder ids (files-destination hashes) currently holding
  /// [folder]. Idempotent per id per month.
  void sampleSeeders(String folder, Iterable<String> seederIds, int nowMs) {
    if (folder.isEmpty) return;
    final ym = ymOf(nowMs);
    _rollover(folder, ym);
    try {
      for (final id in seederIds) {
        if (id.isEmpty) continue;
        _db.execute(
          'INSERT OR IGNORE INTO pop_live(folder, ym, kind, id) VALUES(?,?,0,?)',
          [folder, ym, id],
        );
      }
    } catch (_) {}
  }

  /// Record one leecher (a peer that downloaded from us) of [folder]. Idempotent
  /// per id per month.
  void recordLeecher(String folder, String leecherId, int nowMs) {
    if (folder.isEmpty || leecherId.isEmpty) return;
    final ym = ymOf(nowMs);
    _rollover(folder, ym);
    try {
      _db.execute(
        'INSERT OR IGNORE INTO pop_live(folder, ym, kind, id) VALUES(?,?,1,?)',
        [folder, ym, leecherId],
      );
    } catch (_) {}
  }

  /// The monthly series for [folder], oldest-first, capped to the last [months].
  /// The current month is counted live from `pop_live`; finished months come
  /// from `pop_month`.
  List<PopMonth> series(String folder, int nowMs, {int months = 12}) {
    final curYm = ymOf(nowMs);
    _rollover(folder, curYm);
    final byYm = <int, PopMonth>{};
    try {
      for (final r in _db.select(
          'SELECT ym, seeders, leechers FROM pop_month WHERE folder=?', [folder])) {
        final ym = r['ym'] as int;
        byYm[ym] = PopMonth(ym, (r['seeders'] as int?) ?? 0, (r['leechers'] as int?) ?? 0);
      }
      final live = _db.select(
        'SELECT '
        '  SUM(CASE WHEN kind=0 THEN 1 ELSE 0 END) AS s, '
        '  SUM(CASE WHEN kind=1 THEN 1 ELSE 0 END) AS l '
        'FROM pop_live WHERE folder=? AND ym=?',
        [folder, curYm],
      );
      final s = live.isEmpty ? 0 : (live.first['s'] as int?) ?? 0;
      final l = live.isEmpty ? 0 : (live.first['l'] as int?) ?? 0;
      byYm[curYm] = PopMonth(curYm, s, l);
    } catch (_) {
      return const [];
    }
    final all = byYm.values.toList()..sort((a, b) => a.ym.compareTo(b.ym));
    return all.length > months ? all.sublist(all.length - months) : all;
  }

  void close() {
    try {
      _db.dispose();
    } catch (_) {}
  }
}
