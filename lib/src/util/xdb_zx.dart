/// The zxdb implementation of [XDb]: a `.zx` file opened in this isolate,
/// or a database in memory.
library;

import 'dart:io';

import 'package:zx/zx.dart' show SevenZipException;
import 'package:zx/zxdb.dart';

import 'xdb.dart';

/// Store options for every database this package and the app open.
///
/// LZ4 pages (`fast`): zxdb's default `max` decodes at about 85 KB/s on a
/// cold read, which a phone cannot afford on a lookup. Small caches: a
/// phone holds two dozen of these open, and zxdb's defaults (128 MiB of
/// pages, 32 MiB of blocks) are sized for one big database on a desktop.
/// Not durable: a commit is not fsynced. Copy-on-write means a crash can
/// lose the last commits but never corrupts what came before; [durable]
/// opens a store whose last commit must survive a power cut.
ZxDbStoreOptions xdbStoreOptions({bool durable = false}) => ZxDbStoreOptions(
      compression: 'fast',
      durable: durable,
      pageCacheBytes: 4 << 20,
      blockCacheBytes: 2 << 20,
      txnMemoryBytes: 16 << 20,
      lsmMemBytes: 4 << 20,
    );

/// Opens (creating it if missing) the database file at [path]. [password]
/// encrypts it (AES-256); null leaves it plain. A second open of the same
/// file in this isolate shares the first handle's database, as SQLite
/// connections shared one file; [XDb.dispose] closes it with the last.
XDb xdbOpenFile(String path,
    {String? password, bool readOnly = false, bool durable = false}) {
  final abs = File(path).absolute.path;
  final have = _open[abs];
  if (have != null) {
    have.refs++;
    return _ZxXDb(have);
  }
  try {
    File(abs).parent.createSync(recursive: true);
    final db = ZxDatabase.open(abs,
        password: password,
        readOnly: readOnly,
        create: !readOnly,
        options: xdbStoreOptions(durable: durable));
    final f = _ZxFile(abs, db);
    _open[abs] = f;
    return _ZxXDb(f);
  } on ZxDbException catch (e) {
    throw XDbException(e.message, e.kind);
  } on SevenZipException catch (e) {
    throw XDbException('$abs: ${e.message} (wrong password or not a '
        'database)', ZxDbError.corrupt);
  }
}

/// A database that lives in memory only (tests, caches).
XDb xdbOpenMemory() => _ZxXDb(_ZxFile.memory());

final Map<String, _ZxFile> _open = {};

/// One open database, shared by the handles of this isolate.
class _ZxFile {
  _ZxFile(this.path, this.db)
      : sql = ZxSql(db!.store),
        memory = false {
    _baseline = _length();
  }

  _ZxFile.memory()
      : path = null,
        db = null,
        sql = ZxSql(ZxMemoryStore()),
        memory = true;

  final String? path;
  final ZxDatabase? db;
  ZxSql sql;
  final bool memory;
  int refs = 1;

  /// Bumped when [sql] is replaced (after a compaction), so prepared
  /// statements know to parse again.
  int epoch = 0;

  int _baseline = 0;
  int _sinceCheck = 0;

  int _length() {
    final p = path;
    if (p == null) return 0;
    try {
      return File(p).lengthSync();
    } catch (_) {
      return 0;
    }
  }

  /// After a statement outside a transaction: every so often, compact
  /// when the file has doubled since the last compaction (plus 4 MiB, so
  /// a small store is not rewritten over a few KiB).
  void afterCommit() {
    if (memory || db!.readOnly) return;
    if (++_sinceCheck < 32) return;
    _sinceCheck = 0;
    final now = _length();
    if (now > 2 * _baseline + (4 << 20)) compact();
  }

  void compact() {
    final d = db;
    if (d == null || d.readOnly || sql.inTransaction) return;
    sql.close();
    try {
      d.vacuum(keep: 1);
    } finally {
      sql = ZxSql(d.store);
      epoch++;
      _baseline = _length();
    }
  }

  void close() {
    sql.close();
    db?.close();
    final p = path;
    if (p != null && identical(_open[p], this)) _open.remove(p);
  }
}

class _ZxXDb extends XDb {
  _ZxXDb(this._f);
  final _ZxFile _f;
  bool _disposed = false;
  int _changes = 0;
  int _lastRowid = 0;

  ZxSqlResult _run(String sql, List<Object?> params) {
    if (_disposed) throw XDbException('the database is closed');
    final ZxSqlResult r;
    try {
      r = _f.sql.execute(sql, params);
    } on ZxDbException catch (e) {
      throw XDbException(e.message, e.kind);
    }
    _changes = r.changes;
    _lastRowid = r.lastInsertRowid;
    if (!_f.sql.inTransaction) _f.afterCommit();
    return r;
  }

  @override
  void execute(String sql, [List<Object?> params = const []]) =>
      _run(sql, params);

  @override
  XRows select(String sql, [List<Object?> params = const []]) {
    final r = _run(sql, params);
    return XRows(r.columns, r.rows);
  }

  @override
  XStatement prepare(String sql) => _ZxStatement(this, sql);

  @override
  int get updatedRows => _changes;

  @override
  int get lastInsertRowId => _lastRowid;

  @override
  bool get inTransaction => _f.sql.inTransaction;

  @override
  int get bytes => _f._length();

  @override
  String? get path => _f.path;

  @override
  void compact() => _f.compact();

  @override
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    if (--_f.refs <= 0) _f.close();
  }
}

class _ZxStatement extends XStatement {
  _ZxStatement(this._db, this._text);
  final _ZxXDb _db;
  final String _text;
  ZxSqlStatement? _st;
  int _epoch = -1;

  ZxSqlResult _run(List<Object?> params) {
    final f = _db._f;
    if (_db._disposed) throw XDbException('the database is closed');
    if (_st == null || _epoch != f.epoch) {
      try {
        _st = f.sql.prepare(_text);
      } on ZxDbException catch (e) {
        throw XDbException(e.message, e.kind);
      }
      _epoch = f.epoch;
    }
    final ZxSqlResult r;
    try {
      r = _st!.execute(params);
    } on ZxDbException catch (e) {
      throw XDbException(e.message, e.kind);
    }
    _db._changes = r.changes;
    _db._lastRowid = r.lastInsertRowid;
    if (!f.sql.inTransaction) f.afterCommit();
    return r;
  }

  @override
  void execute([List<Object?> params = const []]) => _run(params);

  @override
  XRows select([List<Object?> params = const []]) {
    final r = _run(params);
    return XRows(r.columns, r.rows);
  }

  @override
  void dispose() => _st = null;
}
