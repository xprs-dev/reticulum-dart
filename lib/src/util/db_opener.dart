/// Injectable opener for every file-backed database this package creates
/// (media archive, disk index, serve stats, relay event store, coin
/// wallet). Every store holds an [XDb] (xdb.dart): zxdb, pure Dart.
///
/// Host apps that encrypt their storage (XPRS's encrypted profiles) set
/// [dbOpener] once at boot to an opener that passes the right password
/// for the database's path. The default opens the file plain.
///
/// In-memory databases go through [dbMemoryOpener] for the same reason.
library;

import 'dart:typed_data';

import 'file_system.dart';
import 'xdb.dart';
import 'xdb_zx.dart' as zx;

/// Signature of a database opener: absolute path in, open handle out.
typedef DbOpener = XDb Function(String path);

/// Signature of an in-memory database opener.
typedef DbMemoryOpener = XDb Function();

/// The opener used by all file-backed stores in this package. Replace at
/// boot, BEFORE any store is constructed; swapping it later does not
/// re-open already-open handles. The path `:memory:` opens a database in
/// memory, as SQLite did (stores and tests pass it through).
DbOpener dbOpener =
    (path) => path == ':memory:' ? dbMemoryOpener() : zx.xdbOpenFile(path);

/// The opener used for in-memory databases (tests, the coin wallet's
/// in-memory mode).
DbMemoryOpener dbMemoryOpener = zx.xdbOpenMemory;

// ── Blobs next to the databases ──────────────────────────────────────────
//
// Large values live in files beside the database, not in rows (xdb.dart:
// a compaction rewrites every live page). A host that encrypts its storage
// injects these three as well, so the bytes are as protected as the rows
// that describe them; the defaults read and write the file as it is.

/// Read the blob file at [path]; null when it does not exist.
Uint8List? Function(String path) blobRead = (path) {
  final f = fileSystem.file(path);
  return f.existsSync() ? f.readAsBytesSync() : null;
};

/// Write the blob file at [path] (its folder is created), replacing it.
void Function(String path, Uint8List bytes) blobWrite = (path, bytes) {
  final f = fileSystem.file(path);
  f.parent.createSync(recursive: true);
  // Through a temporary name: a reader never sees half a blob.
  final tmp = fileSystem.file('$path.tmp');
  tmp.writeAsBytesSync(bytes, flush: true);
  tmp.renameSync(path);
};

/// Remove the blob file at [path]; nothing when it is absent.
void Function(String path) blobDelete = (path) {
  final f = fileSystem.file(path);
  if (f.existsSync()) f.deleteSync();
};
