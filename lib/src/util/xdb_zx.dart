/// Opening [XDb]s with the options this package's stores run with.
library;

import 'package:zx/zxdb.dart';

import 'xdb.dart';

/// Store options for every database this package and the app open.
///
/// LZ4 pages (`fast`): zxdb's default `max` decodes at about 85 KB/s on a
/// cold read, which a phone cannot afford on a lookup. Small caches: a
/// phone holds two dozen of these open, and zxdb's defaults (128 MiB of
/// pages, 32 MiB of blocks) are sized for one big database on a desktop.
/// Not durable: a commit is not fsynced. Copy-on-write means a crash can
/// lose the last commits but never corrupts what came before; [durable]
/// opens a store whose last commit must survive a power cut.
///
/// Passwords given to these stores are random keys (HKDF outputs of the
/// profile master key, 256 bits), never words a person typed: scrypt's
/// stretching adds nothing to them and its default cost (about a second
/// per open on a phone, two dozen stores per unlock) is skipped
/// (`scryptLog2N: 1`, kept in each file's header).
ZxDbStoreOptions xdbStoreOptions({bool durable = false}) => ZxDbStoreOptions(
      compression: 'fast',
      durable: durable,
      pageCacheBytes: 4 << 20,
      blockCacheBytes: 2 << 20,
      txnMemoryBytes: 16 << 20,
      lsmMemBytes: 4 << 20,
      scryptLog2N: 1,
    );

/// Opens (creating it if missing) the database file at [path]; `:memory:`
/// is a database in memory. [password] encrypts it (AES-256); null leaves
/// it plain. A second open of the same file in this isolate shares the
/// first handle's database; [XDb.dispose] closes it with the last.
XDb xdbOpenFile(String path,
        {String? password, bool readOnly = false, bool durable = false}) =>
    zxDbOpenFile(path,
        password: password,
        readOnly: readOnly,
        options: xdbStoreOptions(durable: durable));

/// A database that lives in memory only (tests, caches).
XDb xdbOpenMemory() => zxDbOpenMemory();
