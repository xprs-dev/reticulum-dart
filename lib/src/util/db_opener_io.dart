/// Native default openers: package:sqlite3's FFI binding. The only file in
/// this package that imports the FFI half of sqlite3.
library;

import 'package:sqlite3/common.dart';
import 'package:sqlite3/sqlite3.dart';

CommonDatabase defaultDbOpener(String path) => sqlite3.open(path);

CommonDatabase defaultDbMemoryOpener() => sqlite3.openInMemory();
