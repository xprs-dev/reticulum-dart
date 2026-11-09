/// Injectable opener for every file-backed database this package creates
/// (media archive, disk index, serve stats, relay event store, coin wallet):
/// zxdb files (package:zx/zxdb.dart, `ZxSqlDb`).
///
/// Host apps that encrypt their storage (XPRS's encrypted profiles) set
/// [dbOpener] once at boot to an opener that applies the right key for the
/// database's path (XPRS core: `openStoreDb`). The default opens a plain
/// file, the same on every platform: zxdb runs natively and in the browser
/// (dart2wasm; the host persists its files there).
///
/// [durable] asks for a flush to the disk at every commit: for data whose
/// loss on a power cut costs something that cannot be fetched again (the
/// coin wallet's proofs). In-memory databases go through [dbMemoryOpener].
library;

import 'package:zx/zxdb.dart';

export 'package:zx/zxdb.dart'
    show ZxSqlDb, ZxRow, ZxRows, ZxSqlDbStatement, ZxDbException, ZxDbError;

/// Signature of a database opener: absolute path in, open handle out.
/// [autoCompact] false: the store compacts only when it calls
/// `maybeCompact` (a store that can grow large, compacted where a pause
/// costs nothing).
typedef DbOpener = ZxSqlDb Function(String path,
    {bool durable, bool autoCompact});

/// Signature of an in-memory database opener.
typedef DbMemoryOpener = ZxSqlDb Function();

ZxSqlDb _plain(String path, {bool durable = false, bool autoCompact = true}) =>
    ZxSqlDb.open(path, durable: durable, autoCompact: autoCompact);

/// The opener every store uses; a host replaces it at boot.
DbOpener dbOpener = _plain;

/// The in-memory opener.
DbMemoryOpener dbMemoryOpener = ZxSqlDb.memory;

/// Opens [path] with [dbOpener], or an in-memory database through
/// [dbMemoryOpener] when [path] is `:memory:` (a zxdb file path has no such
/// special name: without this a test's `:memory:` became a file in the
/// working directory, shared by every test).
ZxSqlDb openDb(String path,
        {bool durable = false, bool autoCompact = true}) =>
    path == ':memory:'
        ? dbMemoryOpener()
        : dbOpener(path, durable: durable, autoCompact: autoCompact);
