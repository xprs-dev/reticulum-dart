/// Re-apply the host's choice of native SQLite library on a freshly spawned
/// isolate. package:sqlite3's loader override is per-isolate, so an isolate
/// that opens a database must be told the same thing the main isolate was
/// (XPRS ships SQLCipher, not libsqlite3, on Android) -- or the open throws.
library;

import 'dart:ffi';

import 'package:sqlite3/open.dart' as sqlite_open;

void applySqliteLibraryOverride(String? lib) {
  if (lib == null || lib.isEmpty) return;
  DynamicLibrary open() => DynamicLibrary.open(lib);
  for (final os in sqlite_open.OperatingSystem.values) {
    sqlite_open.open.overrideFor(os, open);
  }
}
