/// Injectable filesystem for every file this package reads or writes
/// (follow sets, relay hub config, partial downloads, and the parent
/// directories of its SQLite files).
///
/// Same shape as [dbOpener]: the default is the real disk on native targets
/// and a host-injected tree on web, where dart:io compiles but every call
/// throws. XPRS injects its own `fs` at boot so the package and the app see
/// one tree. Types are package:file's, which carry the dart:io API (sync
/// variants included), so a call site reads `fileSystem.file(path)` where it
/// read `File(path)`.
library;

import 'package:file/file.dart';

import 'file_system_stub.dart' if (dart.library.io) 'file_system_io.dart'
    as platform;

FileSystem fileSystem = platform.defaultFileSystem;
