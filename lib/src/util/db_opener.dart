/// Injectable SQLite opener for every file-backed database this package
/// creates (media archive, disk index, serve stats, relay event store,
/// coin wallet).
///
/// Host apps that encrypt their storage (aurora's encrypted profiles) set
/// [dbOpener] once at boot to an opener that applies the right SQLCipher
/// key based on the database path. The default is a plain `sqlite3.open`,
/// so nothing changes for hosts that don't inject.
///
/// In-memory databases don't go through this hook.
library;

import 'package:sqlite3/sqlite3.dart';

/// Signature of a database opener: absolute path in, open handle out.
typedef DbOpener = Database Function(String path);

/// The opener used by all file-backed stores in this package. Replace at
/// boot, BEFORE any store is constructed; swapping it later does not rekey
/// already-open handles.
DbOpener dbOpener = sqlite3.open;
