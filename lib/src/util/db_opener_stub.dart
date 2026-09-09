/// Web default openers: none. The browser build of package:sqlite3 needs an
/// asynchronously loaded sqlite3.wasm and a registered IndexedDB VFS, both of
/// which belong to the host, so the host injects `dbOpener` and
/// `dbMemoryOpener` at boot. Reaching a store before that is a bug.
library;

import 'package:sqlite3/common.dart';

Never _notInjected(String what) => throw StateError(
    'reticulum: $what not injected -- on web the host must set '
    'dbOpener/dbMemoryOpener (sqlite3.wasm + IndexedDB VFS) before any '
    'store is constructed');

CommonDatabase defaultDbOpener(String path) => _notInjected('dbOpener');

CommonDatabase defaultDbMemoryOpener() => _notInjected('dbMemoryOpener');
