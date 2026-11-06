/// XDb: the one database handle every store in this package (and the XPRS
/// app) persists through. It is zxdb's ZxDb (package:zx, pure Dart, no
/// FFI): a SQL database inside a `.zx` file, SQLite's dialect, encrypted by
/// password, written copy-on-write so a crash keeps the last commit, behind
/// the slice of package:sqlite3 the stores used when they ran on SQLite.
///
/// What every store has to respect (package:zx/zxdb.dart, ZxDb):
///
///  * A statement outside `BEGIN ... COMMIT` is a commit of its own, about
///    a millisecond and a few KiB appended to the file. A store that writes
///    several rows at once wraps them in [XDb.transaction] (or BEGIN /
///    COMMIT): one commit for the batch.
///  * The file is compacted by the handle when it has doubled; a store never
///    schedules VACUUM. PRAGMAs that managed SQLite's file are accepted and
///    do nothing. A byte budget reads [XDb.liveBytes], not [XDb.bytes].
///  * Large blobs belong in files next to the database (MediaArchive's
///    blobs, through blobRead / blobWrite), not in rows.
library;

import 'package:zx/zxdb.dart';

/// The handle (zxdb's ZxDb).
typedef XDb = ZxDb;

/// One row of a SELECT: a read-only `Map<String, dynamic>`.
typedef XRow = ZxRow;

/// The rows of a SELECT, a list, with `columnNames`.
typedef XRows = ZxRows;

/// A prepared statement.
typedef XStatement = ZxDbStatement;

/// A failed statement, with SQLite's wording (`UNIQUE constraint failed:
/// t.a`), and a wrong password or a file that is not a database.
typedef XDbException = ZxDbException;
