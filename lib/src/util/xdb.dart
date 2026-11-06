/// XDb: the one database handle every store in this package (and the XPRS
/// app) persists through. It is zxdb (package:zx, pure Dart, no FFI): a
/// SQL database inside a `.zx` file, SQLite's dialect, encrypted by
/// password, written copy-on-write so a crash keeps the last commit.
///
/// The surface is deliberately the slice of package:sqlite3 the stores
/// used when they ran on SQLite — `execute`, `select` (rows read as maps),
/// `prepare`, `updatedRows`, `lastInsertRowId`, `dispose` — so a store's SQL
/// stays as it was. What differs, and what every store has to respect:
///
///  * A statement outside `BEGIN ... COMMIT` is a commit of its own, about
///    a millisecond and a few KiB appended to the file. A store that writes
///    several rows at once wraps them in a transaction ([transaction] or
///    BEGIN/COMMIT): one commit for the batch.
///  * The file grows with every commit (copy-on-write) and is compacted
///    here when it reaches twice its size after the last compaction
///    ([compact]); a store never schedules VACUUM itself. PRAGMAs that
///    managed SQLite's file (journal_mode, incremental_vacuum,
///    wal_checkpoint, busy_timeout, page_count) are accepted and do nothing;
///    [bytes] is the file's size.
///  * Large blobs belong in files next to the database, not in rows: a
///    compaction rewrites every live page, blobs included.
library;

import 'dart:collection';

import 'package:zx/zxdb.dart';

/// A failed statement: the database's message (SQLite's wording, such as
/// `UNIQUE constraint failed: t.a`) and its kind.
class XDbException implements Exception {
  XDbException(this.message, [this.kind]);
  final String message;
  final ZxDbError? kind;

  /// The database file is not one this key opens, or is not a database.
  bool get isNotADatabase =>
      kind == ZxDbError.corrupt || message.contains('password');

  @override
  String toString() => 'XDbException: $message';
}

/// One row: a read-only map from column name to value, also indexable by
/// column position (`row[0]`), as package:sqlite3's Row was.
class XRow extends MapBase<String, dynamic> {
  XRow._(this._names, this._index, this._values);
  final List<String> _names;
  final Map<String, int> _index;
  final List<Object?> _values;

  // dynamic, as package:sqlite3's Row was: a store reads `row['n'] as int`
  // and `row['name']` into a String parameter without a cast each time.
  @override
  dynamic operator [](Object? key) {
    if (key is int) return _values[key];
    final i = _index[key];
    return i == null ? null : _values[i];
  }

  /// The value of column [i].
  dynamic columnAt(int i) => _values[i];

  @override
  Iterable<String> get keys => _names;

  @override
  Iterable<dynamic> get values => _values;

  @override
  int get length => _names.length;

  @override
  bool containsKey(Object? key) => _index.containsKey(key);

  @override
  void operator []=(String key, dynamic value) =>
      throw UnsupportedError('a row is read only');
  @override
  void clear() => throw UnsupportedError('a row is read only');
  @override
  dynamic remove(Object? key) => throw UnsupportedError('a row is read only');
}

/// The rows of a SELECT, in order; a list, as package:sqlite3's ResultSet.
class XRows extends ListBase<XRow> {
  XRows(this.columnNames, List<List<Object?>> rows)
      : _rows = rows,
        _index = {
          for (var i = columnNames.length - 1; i >= 0; i--) columnNames[i]: i
        };

  static final XRows empty = XRows(const [], const []);

  final List<String> columnNames;
  final List<List<Object?>> _rows;
  final Map<String, int> _index;

  /// The raw values, row by row.
  List<List<Object?>> get rows => _rows;

  @override
  int get length => _rows.length;
  @override
  set length(int n) => throw UnsupportedError('rows are read only');
  @override
  XRow operator [](int i) => XRow._(columnNames, _index, _rows[i]);
  @override
  void operator []=(int i, XRow v) =>
      throw UnsupportedError('rows are read only');
}

/// A statement parsed once and run many times.
abstract class XStatement {
  void execute([List<Object?> params = const []]);
  XRows select([List<Object?> params = const []]);
  void dispose();
}

/// The handle. See the library comment.
abstract class XDb {
  /// Runs one or more statements (separated by `;`).
  void execute(String sql, [List<Object?> params = const []]);

  /// Runs a query and returns its rows.
  XRows select(String sql, [List<Object?> params = const []]);

  XStatement prepare(String sql);

  /// Rows inserted, updated or deleted by the last statement.
  int get updatedRows;

  /// The rowid of the last row inserted.
  int get lastInsertRowId;

  /// True between BEGIN and COMMIT / ROLLBACK.
  bool get inTransaction;

  /// Runs [body] in one transaction (one commit): rolled back when it
  /// throws. Inside an open transaction it simply runs [body].
  T transaction<T>(T Function() body) {
    if (inTransaction) return body();
    execute('BEGIN');
    try {
      final r = body();
      execute('COMMIT');
      return r;
    } catch (_) {
      try {
        execute('ROLLBACK');
      } catch (_) {}
      rethrow;
    }
  }

  /// The database's size on disk, bytes (0 in memory): what the disk
  /// pays, history included until the next compaction.
  int get bytes;

  /// The live data, bytes before compression: the pages the last commit
  /// uses times the page size (SQLite's page_count * page_size; 0 in
  /// memory). What a byte budget reads — [bytes] would count history the
  /// next compaction drops, and a budget would evict live rows for it.
  int get liveBytes;

  /// The file, or null in memory.
  String? get path;

  /// Drops the history of earlier commits and rewrites the file to its
  /// live pages. Runs by itself when the file has doubled; a store calls
  /// it only where SQLite needed an explicit VACUUM, and outside a
  /// transaction.
  void compact();

  /// Closes the handle (the file stays open while another handle of this
  /// isolate shares it).
  void dispose();
}
