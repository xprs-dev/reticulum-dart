/// Injectable SQLite opener for every file-backed database this package
/// creates (media archive, disk index, serve stats, relay event store,
/// coin wallet).
///
/// Host apps that encrypt their storage (XPRS's encrypted profiles) set
/// [dbOpener] once at boot to an opener that applies the right SQLCipher
/// key based on the database path. The default is a plain `sqlite3.open`
/// on native targets, so nothing changes for hosts that don't inject.
///
/// Every store types its handle as [CommonDatabase] (package:sqlite3/common)
/// rather than the FFI `Database`, because the browser build of the same
/// package (package:sqlite3/wasm) returns a `CommonDatabase` backed by
/// sqlite3.wasm over IndexedDB. The FFI half is only ever imported from
/// `db_opener_io.dart`, which is what keeps `dart:ffi` out of the web build.
/// A web host MUST inject both openers before any store is constructed; the
/// web default throws so a forgotten injection is loud, not a plaintext or
/// in-memory surprise.
///
/// In-memory databases go through [dbMemoryOpener] for the same reason.
library;

import 'package:sqlite3/common.dart';

import 'db_opener_stub.dart' if (dart.library.io) 'db_opener_io.dart'
    as platform;

/// Signature of a database opener: absolute path in, open handle out.
typedef DbOpener = CommonDatabase Function(String path);

/// Signature of an in-memory database opener.
typedef DbMemoryOpener = CommonDatabase Function();

/// The opener used by all file-backed stores in this package. Replace at
/// boot, BEFORE any store is constructed; swapping it later does not rekey
/// already-open handles.
DbOpener dbOpener = platform.defaultDbOpener;

/// The opener used for `:memory:` databases (tests, the coin wallet's
/// in-memory mode).
DbMemoryOpener dbMemoryOpener = platform.defaultDbMemoryOpener;
